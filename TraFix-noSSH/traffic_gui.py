#!/usr/bin/env python3
"""
traffic_gui.py — Network Traffic Simulator GUI (DNS-based, no SSH to targets)
Sandboxed cybersecurity training environment tool.

This tool runs ON the same host as dnsmasq and mock_server.py.
It manages dnsmasq config locally and drives curl traffic from this host
(or optionally via SSH to targets for traffic generation only).

Architecture:
  - GUI host = DNS server (dnsmasq) + HTTP mock server (mock_server.py)
  - Target hosts have /etc/resolv.conf pointing to this host's IP (set once manually)
  - GUI writes /etc/dnsmasq.d/traffic-sim.conf and restarts dnsmasq locally
  - Traffic generation runs curl locally (simulating requests) or via SSH to targets

Requirements:
    pip install paramiko
    sudo apt install dnsmasq
    sudo systemctl enable dnsmasq

Usage:
    python3 traffic_gui.py
    (needs sudo or membership in group that can write /etc/dnsmasq.d/ and restart dnsmasq)
"""

import ipaddress
import os
import queue
import subprocess
import threading
import time
import tkinter as tk
from tkinter import font as tkfont
from tkinter import messagebox, scrolledtext, ttk

try:
    import paramiko
    HAS_PARAMIKO = True
except ImportError:
    HAS_PARAMIKO = False

# ── Constants ─────────────────────────────────────────────────────────────────

TOP_20_DOMAINS = [
    "google.com",
    "youtube.com",
    "facebook.com",
    "amazon.com",
    "wikipedia.org",
    "twitter.com",
    "x.com",
    "reddit.com",
    "instagram.com",
    "linkedin.com",
    "netflix.com",
    "bing.com",
    "microsoft.com",
    "apple.com",
    "espn.com",
    "cnn.com",
    "nytimes.com",
    "twitch.tv",
    "ebay.com",
    "yahoo.com",
    "zoom.us",
]

DNSMASQ_CONF_PATH = "/etc/dnsmasq.d/traffic-sim.conf"
DNSMASQ_CONF_HEADER = "# traffic-sim — managed by traffic_gui.py — DO NOT EDIT MANUALLY\n"

# ── dnsmasq helpers ───────────────────────────────────────────────────────────

def build_dnsmasq_conf(mock_ip, domains):
    """Generate dnsmasq address= lines for all selected domains."""
    lines = [DNSMASQ_CONF_HEADER]
    for d in domains:
        lines.append(f"address=/{d}/{mock_ip}")
        lines.append(f"address=/www.{d}/{mock_ip}")
    return "\n".join(lines) + "\n"

def write_dnsmasq_conf(mock_ip, domains):
    """Write the dnsmasq config file. Requires write access to /etc/dnsmasq.d/."""
    content = build_dnsmasq_conf(mock_ip, domains)
    os.makedirs(os.path.dirname(DNSMASQ_CONF_PATH), exist_ok=True)
    with open(DNSMASQ_CONF_PATH, "w") as f:
        f.write(content)

def remove_dnsmasq_conf():
    """Remove the traffic-sim dnsmasq config file."""
    if os.path.exists(DNSMASQ_CONF_PATH):
        os.remove(DNSMASQ_CONF_PATH)

def restart_dnsmasq():
    """Restart dnsmasq via systemctl. Returns (success, output)."""
    result = subprocess.run(
        ["sudo", "systemctl", "restart", "dnsmasq"],
        capture_output=True, text=True, timeout=15
    )
    return result.returncode == 0, (result.stdout + result.stderr).strip()

def get_dnsmasq_status():
    """Returns (active: bool, status_line: str)."""
    result = subprocess.run(
        ["systemctl", "is-active", "dnsmasq"],
        capture_output=True, text=True, timeout=5
    )
    active = result.stdout.strip() == "active"
    return active, result.stdout.strip()

def check_dnsmasq_installed():
    result = subprocess.run(["which", "dnsmasq"], capture_output=True, text=True)
    return result.returncode == 0

# ── Traffic generation (local curl) ───────────────────────────────────────────

def run_local_traffic(domains, cycles, delay_sec, log_fn, stop_flag):
    """Run curl requests locally against each domain."""
    log_fn(f"  → Local traffic: {cycles} cycle(s), {delay_sec}s delay between cycles", "info")
    for cycle in range(1, cycles + 1):
        if stop_flag.is_set():
            break
        log_fn(f"  ↻ Cycle {cycle}/{cycles}", "dim")
        for domain in domains:
            if stop_flag.is_set():
                break
            cmd = [
                "curl", "-s", "-o", "/dev/null",
                "-w", "%{http_code}",
                "--max-time", "5",
                "--connect-timeout", "3",
                f"http://{domain}/"
            ]
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=8)
                status = result.stdout.strip() or "???"
                tag = "ok" if status == "200" else "warn"
                log_fn(f"    {domain:<32} HTTP {status}", tag)
            except subprocess.TimeoutExpired:
                log_fn(f"    {domain:<32} TIMEOUT", "fail")
            except Exception as e:
                log_fn(f"    {domain:<32} ERROR: {e}", "fail")
        if cycle < cycles and not stop_flag.is_set():
            time.sleep(delay_sec)
    log_fn("  ✓ Local traffic generation complete", "ok")

# ── SSH traffic generation (optional, targets only) ───────────────────────────

def ssh_run_traffic(ip, user, password, domains, cycles, delay_sec, log_fn, stop_flag):
    """SSH into a target and run curl from there (no sudo needed — just curl)."""
    if not HAS_PARAMIKO:
        log_fn(f"[{ip}] paramiko not installed — skipping remote traffic", "warn")
        return
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(ip, username=user, password=password, timeout=10,
                       allow_agent=False, look_for_keys=False)
    except Exception as e:
        log_fn(f"[{ip}] ✗ SSH failed: {e}", "fail")
        return
    try:
        log_fn(f"[{ip}] → Remote traffic: {cycles} cycle(s)", "info")
        for cycle in range(1, cycles + 1):
            if stop_flag.is_set():
                break
            log_fn(f"[{ip}] ↻ Cycle {cycle}/{cycles}", "dim")
            for domain in domains:
                if stop_flag.is_set():
                    break
                cmd = (f"curl -s -o /dev/null -w '%{{http_code}}' "
                       f"--max-time 5 --connect-timeout 3 http://{domain}/")
                _, stdout, _ = client.exec_command(cmd)
                status = stdout.read().decode(errors="replace").strip() or "???"
                tag = "ok" if status == "200" else "warn"
                log_fn(f"[{ip}]   {domain:<30} HTTP {status}", tag)
            if cycle < cycles and not stop_flag.is_set():
                time.sleep(delay_sec)
        log_fn(f"[{ip}] ✓ Remote traffic complete", "ok")
    finally:
        client.close()

# ── IP range helper ───────────────────────────────────────────────────────────

def expand_ip_range(range_str):
    range_str = range_str.strip()
    if not range_str:
        return []
    if "/" in range_str:
        return [str(ip) for ip in ipaddress.ip_network(range_str, strict=False).hosts()]
    if "-" in range_str:
        base, end = range_str.rsplit("-", 1)
        prefix = ".".join(base.strip().split(".")[:3])
        start  = int(base.strip().split(".")[-1])
        return [f"{prefix}.{i}" for i in range(start, int(end.strip()) + 1)]
    return [ip.strip() for ip in range_str.split(",") if ip.strip()]

# ── GUI ───────────────────────────────────────────────────────────────────────

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Network Traffic Simulator — DNS Mode")
        self.geometry("1000x820")
        self.minsize(860, 680)
        self.configure(bg="#0d1117")
        self.resizable(True, True)

        self._log_queue  = queue.Queue()
        self._stop_flag  = threading.Event()
        self._running    = False

        self._build_ui()
        self._poll_log()
        self._refresh_dns_status()

    # ── UI ────────────────────────────────────────────────────────────────────

    def _build_ui(self):
        BG     = "#0d1117"
        PANEL  = "#161b22"
        BORDER = "#30363d"
        ACCENT = "#58a6ff"
        GREEN  = "#3fb950"
        RED    = "#f85149"
        YELLOW = "#d29922"
        FG     = "#e6edf3"
        DIM    = "#8b949e"
        MONO   = tkfont.Font(family="Monospace", size=9)

        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TProgressbar", troughcolor=PANEL, background=ACCENT,
                        bordercolor=BORDER, lightcolor=ACCENT, darkcolor=ACCENT)
        style.configure("Custom.Treeview",
                        background=PANEL, foreground=FG, rowheight=22,
                        fieldbackground=PANEL, borderwidth=0)
        style.configure("Custom.Treeview.Heading",
                        background="#21262d", foreground=DIM,
                        relief="flat", font=("Sans", 8))
        style.map("Custom.Treeview", background=[("selected", "#1f2937")])

        # ── Title bar ────────────────────────────────────────────────────────
        hdr = tk.Frame(self, bg=BG, pady=10)
        hdr.pack(fill="x", padx=20)
        tk.Label(hdr, text="⚡  Network Traffic Simulator",
                 font=("Sans", 14, "bold"), bg=BG, fg=ACCENT).pack(side="left")
        tk.Label(hdr, text="DNS Mode · Sandboxed Lab",
                 font=("Sans", 9), bg=BG, fg=DIM).pack(side="left", padx=12)

        # DNS status pill (top right)
        self._dns_frame = tk.Frame(hdr, bg=PANEL, bd=1, relief="solid",
                                   highlightbackground=BORDER)
        self._dns_frame.pack(side="right")
        self._dns_dot = tk.Label(self._dns_frame, text="●", font=("Sans", 11),
                                 bg=PANEL, fg=DIM, padx=6, pady=2)
        self._dns_dot.pack(side="left")
        self._dns_lbl = tk.Label(self._dns_frame, text="dnsmasq: checking…",
                                 font=("Sans", 9), bg=PANEL, fg=DIM, padx=6, pady=2)
        self._dns_lbl.pack(side="left")
        tk.Button(self._dns_frame, text="↺", font=("Sans", 9),
                  bg=PANEL, fg=DIM, relief="flat", bd=0,
                  command=self._refresh_dns_status, cursor="hand2").pack(side="left", padx=4)

        tk.Frame(self, bg=BORDER, height=1).pack(fill="x")

        # ── Body split ───────────────────────────────────────────────────────
        body = tk.Frame(self, bg=BG)
        body.pack(fill="both", expand=True)

        left  = tk.Frame(body, bg=BG, width=320)
        right = tk.Frame(body, bg=BG)
        left.pack(side="left", fill="y", padx=(14, 0), pady=12)
        right.pack(side="left", fill="both", expand=True, padx=14, pady=12)
        left.pack_propagate(False)

        # ── Helpers ───────────────────────────────────────────────────────────
        def section(parent, title):
            f = tk.LabelFrame(parent, text=f"  {title}  ",
                              font=("Sans", 9, "bold"),
                              bg=PANEL, fg=ACCENT, bd=1, relief="solid",
                              highlightbackground=BORDER)
            f.pack(fill="x", pady=(0, 10))
            return f

        def field_row(parent, label, var, show=None, hint=None):
            r = tk.Frame(parent, bg=PANEL)
            r.pack(fill="x", padx=10, pady=3)
            tk.Label(r, text=label, width=14, anchor="w",
                     font=("Sans", 9), bg=PANEL, fg=DIM).pack(side="left")
            e = tk.Entry(r, bg="#21262d", fg=FG, relief="flat", bd=4,
                         textvariable=var, show=show,
                         insertbackground=ACCENT, font=("Monospace", 9))
            e.pack(side="left", fill="x", expand=True)
            if hint:
                tk.Label(parent, text=hint, font=("Sans", 7), bg=PANEL,
                         fg=DIM).pack(anchor="w", padx=10, pady=(0, 3))
            return e

        def spin_row(parent, label, var, from_, to, inc=1):
            r = tk.Frame(parent, bg=PANEL)
            r.pack(fill="x", padx=10, pady=3)
            tk.Label(r, text=label, width=14, anchor="w",
                     font=("Sans", 9), bg=PANEL, fg=DIM).pack(side="left")
            s = tk.Spinbox(r, from_=from_, to=to, textvariable=var, increment=inc,
                           width=7, bg="#21262d", fg=FG, relief="flat", bd=4,
                           buttonbackground="#21262d", insertbackground=ACCENT,
                           font=("Monospace", 9))
            s.pack(side="left")

        # ── LEFT: DNS server config ───────────────────────────────────────────
        s1 = section(left, "DNS Server (this host)")
        self._v_mock_ip = tk.StringVar(value="192.168.1.254")
        field_row(s1, "This host's IP", self._v_mock_ip,
                  hint="  Targets must have this in /etc/resolv.conf")

        # dnsmasq conf path (read-only info)
        info = tk.Frame(s1, bg=PANEL)
        info.pack(fill="x", padx=10, pady=(2, 8))
        tk.Label(info, text="Config file", width=14, anchor="w",
                 font=("Sans", 9), bg=PANEL, fg=DIM).pack(side="left")
        tk.Label(info, text=DNSMASQ_CONF_PATH,
                 font=("Monospace", 8), bg=PANEL, fg="#79c0ff").pack(side="left")

        # DNS action buttons
        dns_btns = tk.Frame(s1, bg=PANEL)
        dns_btns.pack(fill="x", padx=10, pady=(0, 8))

        def dns_btn(parent, text, color, cmd):
            b = tk.Button(parent, text=text, command=cmd,
                          bg=color, fg="#0d1117", relief="flat", bd=0,
                          font=("Sans", 9, "bold"), padx=10, pady=5,
                          cursor="hand2", activebackground=color)
            b.pack(side="left", padx=(0, 6))
            return b

        dns_btn(dns_btns, "⚙ Apply DNS",   GREEN,  self._do_apply_dns)
        dns_btn(dns_btns, "✕ Clear DNS",   RED,    self._do_clear_dns)
        dns_btn(dns_btns, "↺ Restart",     YELLOW, self._do_restart_dnsmasq)

        # resolv.conf helper
        s_hint = section(left, "Target Host Setup (once only)")
        hint_text = (
            "On each Ubuntu/Debian target, run:\n\n"
            "  sudo nano /etc/resolv.conf\n\n"
            "Replace nameserver lines with:\n\n"
            "  nameserver <this host's IP>\n\n"
            "To make it permanent (survive reboot):\n\n"
            "  sudo systemctl disable systemd-resolved\n"
            "  sudo rm /etc/resolv.conf\n"
            "  echo 'nameserver <IP>' | sudo tee /etc/resolv.conf"
        )
        tk.Label(s_hint, text=hint_text, font=("Monospace", 8),
                 bg=PANEL, fg=DIM, justify="left",
                 wraplength=260).pack(padx=10, pady=(4, 10))

        # ── LEFT: Traffic options ─────────────────────────────────────────────
        s2 = section(left, "Traffic Generation")

        self._v_traffic_mode = tk.StringVar(value="local")
        mode_frame = tk.Frame(s2, bg=PANEL)
        mode_frame.pack(fill="x", padx=10, pady=(4, 2))
        tk.Label(mode_frame, text="Source", width=14, anchor="w",
                 font=("Sans", 9), bg=PANEL, fg=DIM).pack(side="left")
        tk.Radiobutton(mode_frame, text="Local (this host)",
                       variable=self._v_traffic_mode, value="local",
                       bg=PANEL, fg=FG, selectcolor="#21262d",
                       activebackground=PANEL, font=("Sans", 9),
                       command=self._toggle_ssh_fields).pack(side="left")
        tk.Radiobutton(mode_frame, text="Remote (SSH)",
                       variable=self._v_traffic_mode, value="ssh",
                       bg=PANEL, fg=FG, selectcolor="#21262d",
                       activebackground=PANEL, font=("Sans", 9),
                       command=self._toggle_ssh_fields).pack(side="left", padx=6)

        self._v_cycles  = tk.IntVar(value=3)
        self._v_delay   = tk.DoubleVar(value=2.0)
        self._v_threads = tk.IntVar(value=5)
        spin_row(s2, "Cycles",      self._v_cycles,  1,  100)
        spin_row(s2, "Delay (sec)", self._v_delay,   0.5, 60, 0.5)
        spin_row(s2, "Threads",     self._v_threads, 1,   20)

        # SSH fields (shown only in remote mode)
        self._ssh_frame = tk.Frame(s2, bg=PANEL)
        self._ssh_frame.pack(fill="x")
        tk.Frame(self._ssh_frame, bg=BORDER, height=1).pack(fill="x", padx=10, pady=4)
        tk.Label(self._ssh_frame, text="  SSH (for remote traffic only)",
                 font=("Sans", 8, "italic"), bg=PANEL, fg=DIM).pack(anchor="w", padx=10)

        self._v_ip_range = tk.StringVar(value="192.168.1.1-10")
        self._v_ssh_user = tk.StringVar(value="user")
        self._v_ssh_pass = tk.StringVar()

        field_row(self._ssh_frame, "IP Range", self._v_ip_range,
                  hint="  e.g. 192.168.1.0/24 | 10.0.0.1-20")
        field_row(self._ssh_frame, "SSH User",     self._v_ssh_user)
        field_row(self._ssh_frame, "SSH Password", self._v_ssh_pass, show="•")
        tk.Label(self._ssh_frame,
                 text="  No sudo needed — only curl is run remotely.",
                 font=("Sans", 7, "italic"), bg=PANEL, fg=DIM).pack(anchor="w", padx=10, pady=(0, 6))

        self._ssh_frame.pack_forget()  # hidden by default

        # ── LEFT: Domain selector ─────────────────────────────────────────────
        s3 = section(left, "Domains")
        self._domain_vars = {}
        for d in TOP_20_DOMAINS:
            v = tk.BooleanVar(value=True)
            self._domain_vars[d] = v
            tk.Checkbutton(s3, text=d, variable=v,
                           bg=PANEL, fg=FG, selectcolor="#21262d",
                           activebackground=PANEL, activeforeground=ACCENT,
                           font=("Monospace", 8), anchor="w").pack(fill="x", padx=10)

        dbtns = tk.Frame(s3, bg=PANEL)
        dbtns.pack(fill="x", padx=10, pady=(2, 8))
        tk.Button(dbtns, text="All",  width=5, bg="#21262d", fg=FG, relief="flat", bd=0,
                  command=lambda: [v.set(True)  for v in self._domain_vars.values()]).pack(side="left")
        tk.Button(dbtns, text="None", width=5, bg="#21262d", fg=FG, relief="flat", bd=0,
                  command=lambda: [v.set(False) for v in self._domain_vars.values()]).pack(side="left", padx=6)

        # ── RIGHT panel ───────────────────────────────────────────────────────

        # Action buttons
        btn_row = tk.Frame(right, bg=BG)
        btn_row.pack(fill="x", pady=(0, 10))

        def act_btn(text, color, cmd):
            b = tk.Button(btn_row, text=text, command=cmd,
                          bg=color, fg="#0d1117", relief="flat", bd=0,
                          font=("Sans", 10, "bold"), padx=16, pady=8,
                          cursor="hand2", activebackground=color)
            b.pack(side="left", padx=(0, 8))
            return b

        self._btn_run    = act_btn("▶  Generate Traffic", GREEN,  self._do_run_traffic)
        self._btn_stop   = act_btn("■  Stop",             "#30363d", self._do_stop)
        self._btn_stop.config(state="disabled", fg=DIM)

        tk.Button(btn_row, text="⊘  Clear Log",
                  command=self._clear_log,
                  bg=PANEL, fg=DIM, relief="flat", bd=0,
                  font=("Sans", 9), padx=12, pady=8,
                  cursor="hand2").pack(side="right")

        # Progress bar
        self._progress = ttk.Progressbar(right, mode="indeterminate")
        self._progress.pack(fill="x", pady=(0, 8))

        # DNS config preview
        tk.Label(right, text="ACTIVE DNS CONFIG", font=("Sans", 8, "bold"),
                 bg=BG, fg=DIM, anchor="w").pack(fill="x")
        conf_wrap = tk.Frame(right, bg=PANEL, bd=1, relief="solid",
                             highlightbackground=BORDER)
        conf_wrap.pack(fill="x", pady=(2, 10))
        self._conf_preview = tk.Text(conf_wrap, bg=PANEL, fg="#79c0ff",
                                     font=("Monospace", 8), height=5,
                                     relief="flat", state="disabled",
                                     wrap="none")
        self._conf_preview.pack(fill="x", padx=8, pady=6)

        # Log
        tk.Label(right, text="ACTIVITY LOG", font=("Sans", 8, "bold"),
                 bg=BG, fg=DIM, anchor="w").pack(fill="x")
        self._log = scrolledtext.ScrolledText(
            right, bg=PANEL, fg=FG, font=MONO, relief="flat",
            insertbackground=ACCENT, state="disabled", wrap="word")
        self._log.pack(fill="both", expand=True)

        for tag, color in [("ok", GREEN), ("fail", RED), ("warn", YELLOW),
                           ("info", ACCENT), ("dim", DIM), ("default", FG)]:
            self._log.tag_configure(tag, foreground=color)

    # ── Toggle SSH fields ─────────────────────────────────────────────────────

    def _toggle_ssh_fields(self):
        if self._v_traffic_mode.get() == "ssh":
            self._ssh_frame.pack(fill="x")
        else:
            self._ssh_frame.pack_forget()

    # ── DNS status ────────────────────────────────────────────────────────────

    def _refresh_dns_status(self):
        if not check_dnsmasq_installed():
            self._dns_dot.config(fg="#f85149")
            self._dns_lbl.config(text="dnsmasq: NOT INSTALLED", fg="#f85149")
            return
        active, status = get_dnsmasq_status()
        color = "#3fb950" if active else "#f85149"
        self._dns_dot.config(fg=color)
        self._dns_lbl.config(text=f"dnsmasq: {status}", fg=color)
        self._update_conf_preview()

    def _update_conf_preview(self):
        self._conf_preview.configure(state="normal")
        self._conf_preview.delete("1.0", "end")
        if os.path.exists(DNSMASQ_CONF_PATH):
            try:
                with open(DNSMASQ_CONF_PATH) as f:
                    content = f.read()
                lines = content.splitlines()
                preview = "\n".join(lines[:12])
                if len(lines) > 12:
                    preview += f"\n  … ({len(lines) - 12} more lines)"
                self._conf_preview.insert("end", preview)
            except Exception as e:
                self._conf_preview.insert("end", f"Could not read config: {e}")
        else:
            self._conf_preview.insert("end", "No active config — click ⚙ Apply DNS to deploy.")
        self._conf_preview.configure(state="disabled")

    # ── DNS actions ───────────────────────────────────────────────────────────

    def _do_apply_dns(self):
        domains = [d for d, v in self._domain_vars.items() if v.get()]
        if not domains:
            messagebox.showerror("Validation", "Select at least one domain.")
            return
        mock_ip = self._v_mock_ip.get().strip()
        if not mock_ip:
            messagebox.showerror("Validation", "Enter this host's IP address.")
            return
        try:
            write_dnsmasq_conf(mock_ip, domains)
            self._log_msg(f"Wrote {DNSMASQ_CONF_PATH} ({len(domains)} domains → {mock_ip})", "ok")
        except PermissionError:
            self._log_msg(f"Permission denied writing {DNSMASQ_CONF_PATH}. Run with sudo.", "fail")
            messagebox.showerror("Permission Error",
                                 f"Cannot write to {DNSMASQ_CONF_PATH}.\n\nRun the tool with sudo:\n  sudo python3 traffic_gui.py")
            return
        except Exception as e:
            self._log_msg(f"Failed to write DNS config: {e}", "fail")
            return
        self._do_restart_dnsmasq()

    def _do_clear_dns(self):
        try:
            remove_dnsmasq_conf()
            self._log_msg("Removed traffic-sim DNS config.", "warn")
        except Exception as e:
            self._log_msg(f"Failed to remove DNS config: {e}", "fail")
            return
        self._do_restart_dnsmasq()

    def _do_restart_dnsmasq(self):
        self._log_msg("Restarting dnsmasq…", "dim")
        ok, out = restart_dnsmasq()
        if ok:
            self._log_msg("dnsmasq restarted successfully.", "ok")
        else:
            self._log_msg(f"dnsmasq restart failed: {out}", "fail")
        self.after(500, self._refresh_dns_status)

    # ── Traffic generation ────────────────────────────────────────────────────

    def _do_run_traffic(self):
        domains = [d for d, v in self._domain_vars.items() if v.get()]
        if not domains:
            messagebox.showerror("Validation", "Select at least one domain.")
            return
        mode = self._v_traffic_mode.get()
        if mode == "ssh":
            if not HAS_PARAMIKO:
                messagebox.showerror("Missing dependency",
                                     "paramiko not installed.\nRun: pip install paramiko")
                return
            try:
                ips = expand_ip_range(self._v_ip_range.get())
            except Exception as e:
                messagebox.showerror("Validation", f"Invalid IP range: {e}")
                return
            if not ips:
                messagebox.showerror("Validation", "IP range produced no addresses.")
                return

        self._stop_flag.clear()
        self._set_running(True)
        cycles = self._v_cycles.get()
        delay  = self._v_delay.get()

        if mode == "local":
            threading.Thread(
                target=self._worker_local,
                args=(domains, cycles, delay),
                daemon=True
            ).start()
        else:
            ips     = expand_ip_range(self._v_ip_range.get())
            user    = self._v_ssh_user.get().strip()
            password = self._v_ssh_pass.get()
            threads  = self._v_threads.get()
            threading.Thread(
                target=self._worker_remote,
                args=(ips, user, password, domains, cycles, delay, threads),
                daemon=True
            ).start()

    def _do_stop(self):
        self._stop_flag.set()
        self._log_msg("Stop requested…", "warn")

    def _worker_local(self, domains, cycles, delay):
        self._log_msg("▶ Starting local traffic generation", "info")
        run_local_traffic(domains, cycles, delay, self._log_msg, self._stop_flag)
        if self._stop_flag.is_set():
            self._log_msg("Stopped by user.", "warn")
        self.after(0, lambda: self._set_running(False))

    def _worker_remote(self, ips, user, password, domains, cycles, delay, max_threads):
        self._log_msg(f"▶ Remote traffic → {len(ips)} hosts", "info")
        sem = threading.Semaphore(max_threads)

        def handle(ip):
            if self._stop_flag.is_set():
                return
            with sem:
                ssh_run_traffic(ip, user, password, domains,
                                cycles, delay, self._log_msg, self._stop_flag)

        threads = [threading.Thread(target=handle, args=(ip,), daemon=True) for ip in ips]
        for t in threads: t.start()
        for t in threads: t.join()

        if not self._stop_flag.is_set():
            self._log_msg("All remote hosts complete.", "ok")
        else:
            self._log_msg("Stopped by user.", "warn")
        self.after(0, lambda: self._set_running(False))

    # ── Logging ───────────────────────────────────────────────────────────────

    def _log_msg(self, msg, tag="default"):
        self._log_queue.put((msg, tag))

    def _poll_log(self):
        try:
            while True:
                msg, tag = self._log_queue.get_nowait()
                self._log.configure(state="normal")
                ts = time.strftime("%H:%M:%S")
                self._log.insert("end", f"[{ts}] ", "dim")
                self._log.insert("end", msg + "\n", tag)
                self._log.configure(state="disabled")
                self._log.see("end")
        except Exception:
            pass
        self.after(100, self._poll_log)

    def _clear_log(self):
        self._log.configure(state="normal")
        self._log.delete("1.0", "end")
        self._log.configure(state="disabled")

    # ── State ─────────────────────────────────────────────────────────────────

    def _set_running(self, running):
        self._running = running
        self._btn_run.config( state="disabled" if running else "normal")
        self._btn_stop.config(state="normal"   if running else "disabled")
        if running:
            self._progress.start(12)
        else:
            self._progress.stop()
            self._progress["value"] = 0


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    app = App()
    app.mainloop()
