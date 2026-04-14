#!/usr/bin/env python3
"""
LiteTraFix — Headless Network Traffic Simulator
================================================
Drop this script onto any host that has:
  - dnsmasq installed and enabled
  - mock_server.py running on port 80 (on the DNS/server host)
  - /etc/resolv.conf pointing at the server host IP

Each box runs the script independently — no SSH, no central controller.

Usage:
  sudo python3 litetrafix.py [OPTIONS]

Examples:
  # Apply DNS + generate traffic (3 cycles)
  sudo python3 litetrafix.py --server-ip 192.168.1.254 --apply-dns --cycles 3

  # Generate traffic only (DNS already applied)
  sudo python3 litetrafix.py --cycles 5 --delay 1 --threads 8

  # Use a custom domain subset
  sudo python3 litetrafix.py --server-ip 192.168.1.254 --apply-dns \
      --domains google.com youtube.com reddit.com

  # Clear DNS (restore normal DNS behaviour)
  sudo python3 litetrafix.py --clear-dns

  # Quiet mode — no banner, only OK/WARN/ERR
  sudo python3 litetrafix.py --cycles 3 -q
"""

import argparse
import subprocess
import sys
import os
import time
import threading
from datetime import datetime

# ---------------------------------------------------------------------------
# Configuration defaults
# ---------------------------------------------------------------------------

DNS_CONF_PATH = "/etc/dnsmasq.d/traffic-sim.conf"
DNS_CONF_HEADER = "# traffic-sim — managed by litetrafix.py — DO NOT EDIT MANUALLY\n"

DEFAULT_DOMAINS = [
    "google.com", "youtube.com", "facebook.com", "amazon.com",
    "wikipedia.org", "twitter.com", "x.com", "reddit.com",
    "instagram.com", "linkedin.com", "netflix.com", "bing.com",
    "microsoft.com", "apple.com", "espn.com", "cnn.com",
    "nytimes.com", "twitch.tv", "ebay.com", "yahoo.com", "zoom.us",
]

DEFAULT_CYCLES   = 1
DEFAULT_DELAY    = 2.0   # seconds between requests in a cycle
DEFAULT_THREADS  = 4

# ---------------------------------------------------------------------------
# Logging helpers
# ---------------------------------------------------------------------------

QUIET = False

def ts():
    return datetime.now().strftime("%H:%M:%S")

def log(msg, level="INFO"):
    if QUIET and level == "INFO":
        return
    tag = {"INFO": "\033[36mINFO\033[0m", "OK": "\033[32m OK \033[0m",
           "WARN": "\033[33mWARN\033[0m", "ERR": "\033[31m ERR\033[0m"}.get(level, level)
    print(f"[{ts()}] [{tag}] {msg}", flush=True)

def die(msg):
    log(msg, "ERR")
    sys.exit(1)

# ---------------------------------------------------------------------------
# DNS management
# ---------------------------------------------------------------------------

def build_dns_config(server_ip, domains):
    lines = [DNS_CONF_HEADER]
    for domain in domains:
        bare = domain.lstrip("www.")
        lines.append(f"address=/{bare}/{server_ip}")
        lines.append(f"address=/www.{bare}/{server_ip}")
    return "\n".join(lines) + "\n"

def apply_dns(server_ip, domains):
    log(f"Writing DNS config → {DNS_CONF_PATH}")
    config = build_dns_config(server_ip, domains)
    try:
        with open(DNS_CONF_PATH, "w") as f:
            f.write(config)
    except PermissionError:
        die(f"Cannot write {DNS_CONF_PATH} — run with sudo.")
    log(f"Configured {len(domains)} domain(s) → {server_ip}")
    restart_dnsmasq()

def clear_dns():
    if os.path.exists(DNS_CONF_PATH):
        os.remove(DNS_CONF_PATH)
        log(f"Removed {DNS_CONF_PATH}")
    else:
        log(f"{DNS_CONF_PATH} not found — nothing to remove", "WARN")
    restart_dnsmasq()

def restart_dnsmasq():
    log("Restarting dnsmasq…")
    result = subprocess.run(
        ["systemctl", "restart", "dnsmasq"],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        log(f"dnsmasq restart failed: {result.stderr.strip()}", "ERR")
        log("Try: sudo journalctl -u dnsmasq -n 30", "WARN")
    else:
        log("dnsmasq restarted OK", "OK")

# ---------------------------------------------------------------------------
# Traffic generation — local mode
# ---------------------------------------------------------------------------

def curl_domain_local(domain):
    url = f"http://{domain}/"
    result = subprocess.run(
        ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", "--max-time", "5", url],
        capture_output=True, text=True
    )
    code = result.stdout.strip() or "000"
    level = "OK" if code == "200" else "WARN"
    log(f"curl {url} → HTTP {code}", level)

def run_local_traffic(domains, cycles, delay, threads):
    log(f"Local traffic: {cycles} cycle(s), {threads} thread(s), {delay}s delay")
    for cycle in range(1, cycles + 1):
        log(f"── Cycle {cycle}/{cycles} ──")
        sem = threading.Semaphore(threads)
        active = []

        def worker(d):
            with sem:
                curl_domain_local(d)
                if delay > 0:
                    time.sleep(delay)

        for domain in domains:
            t = threading.Thread(target=worker, args=(domain,), daemon=True)
            t.start()
            active.append(t)

        for t in active:
            t.join()

    log("Local traffic generation complete", "OK")

# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------

BANNER = r"""
  _     _ _       _____          _____ _
 | |   (_) |     |_   _|        |  ___(_)
 | |    _| |_ ___ | |_ __ __ _  | |_   ___  __
 | |   | | __/ _ \| | '__/ _` | |  _| | \ \/ /
 | |___| | ||  __/| | | | (_| | | |   | |>  <
 |_____|_|\__\___\___/_|  \__,_| \_|   |_/_/\_\

 LiteTraFix — Headless Traffic Simulator
"""

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

def parse_args():
    p = argparse.ArgumentParser(
        description="LiteTraFix — headless DNS + traffic simulator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    # DNS
    dns_grp = p.add_argument_group("DNS")
    dns_grp.add_argument("--server-ip", metavar="IP",
        help="This host's LAN IP (required for --apply-dns)")
    dns_grp.add_argument("--apply-dns", action="store_true",
        help="Write dnsmasq config and restart dnsmasq")
    dns_grp.add_argument("--clear-dns", action="store_true",
        help="Remove dnsmasq config and restart dnsmasq")
    dns_grp.add_argument("--domains", nargs="+", metavar="DOMAIN",
        help=f"Domains to simulate (default: all {len(DEFAULT_DOMAINS)})")

    # Traffic
    traf_grp = p.add_argument_group("Traffic")
    traf_grp.add_argument("--cycles", type=int, default=DEFAULT_CYCLES,
        help=f"Number of traffic cycles (default: {DEFAULT_CYCLES})")
    traf_grp.add_argument("--delay", type=float, default=DEFAULT_DELAY,
        help=f"Seconds between requests (default: {DEFAULT_DELAY})")
    traf_grp.add_argument("--threads", type=int, default=DEFAULT_THREADS,
        help=f"Concurrent threads (default: {DEFAULT_THREADS})")

    # Misc
    p.add_argument("-q", "--quiet", action="store_true",
        help="Suppress INFO messages (only OK/WARN/ERR)")
    p.add_argument("--show-dns", action="store_true",
        help="Print the current dnsmasq config and exit")

    return p.parse_args()

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    global QUIET
    args = parse_args()
    QUIET = args.quiet

    if not QUIET:
        print(BANNER)

    domains = args.domains or DEFAULT_DOMAINS

    # ── Show DNS config ──────────────────────────────────────────────────
    if args.show_dns:
        if os.path.exists(DNS_CONF_PATH):
            print(open(DNS_CONF_PATH).read())
        else:
            log(f"{DNS_CONF_PATH} does not exist", "WARN")
        sys.exit(0)

    # ── Clear DNS ────────────────────────────────────────────────────────
    if args.clear_dns:
        clear_dns()
        if not args.apply_dns and not args.mode:
            sys.exit(0)

    # ── Apply DNS ────────────────────────────────────────────────────────
    if args.apply_dns:
        if not args.server_ip:
            die("--server-ip is required with --apply-dns")
        apply_dns(args.server_ip, domains)

    # ── Traffic generation ───────────────────────────────────────────────
    if args.cycles:
        run_local_traffic(domains, args.cycles, args.delay, args.threads)
    elif not args.apply_dns and not args.clear_dns:
        die("Nothing to do — specify --apply-dns, --clear-dns, or --cycles. Use -h for help.")

    log("Done.", "OK")

if __name__ == "__main__":
    main()
