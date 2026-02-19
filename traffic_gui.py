#!/usr/bin/env python3
"""
traffic_gui.py — Network Traffic Simulator GUI
Sandboxed cybersecurity training environment tool.

Connects to hosts via SSH (password auth), modifies /etc/hosts to point
the top 20 US domains at your mock server, then drives HTTP traffic from
those hosts using curl.

Requirements:
    pip install paramiko
    pip install tkinter   # usually built-in on Linux

Usage:
    python3 traffic_gui.py
"""

import ipaddress
import json
import os
import queue
import threading
import time
import tkinter as tk
from tkinter import font as tkfont
from tkinter import messagebox, scrolledtext, ttk

try:
    import paramiko
except ImportError:
    print("ERROR: paramiko not installed. Run: pip install paramiko")
    raise

# ─── Top 20 US domains ───────────────────────────────────────────────────────

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

HOSTS_MARKER_START = "# === TRAFFIC-SIM START ==="
HOSTS_MARKER_END   = "# === TRAFFIC-SIM END ==="

# ─── SSH helpers ─────────────────────────────────────────────────────────────

def ssh_connect(ip, username, password, timeout=10):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(ip, username=username, password=password, timeout=timeout,
                   allow_agent=False, look_for_keys=False)
    return client

def ssh_run(client, cmd, use_sudo=False, password=None):
    """Run a command; optionally feed sudo password via stdin."""
    if use_sudo:
        cmd = f"sudo -S sh -c '{cmd}'"
    stdin, stdout, stderr = client.exec_command(cmd, get_pty=use_sudo)
    if use_sudo and password:
        stdin.write(password + "\n")
        stdin.flush()
    out = stdout.read().decode(errors="replace").strip()
    err = stderr.read().decode(errors="replace").strip()
    rc  = stdout.channel.recv_exit_status()
    return rc, out, err

def build_hosts_block(mock_ip, domains):
    lines = [HOSTS_MARKER_START]
    for d in domains:
        lines.append(f"{mock_ip}  {d} www.{d}")
    lines.append(HOSTS_MARKER_END)
    return "\n".join(lines)

def inject_hosts(client, mock_ip, domains, password, log_fn):
    """Add or replace traffic-sim block in /etc/hosts."""
    rc, current, err = ssh_run(client, "cat /etc/hosts")
    if rc != 0:
        log_fn(f"  ✗ Could not read /etc/hosts: {err}")
        return False

    # Remove old block if present
    lines = current.splitlines()
    new_lines = []
    inside = False
    for line in lines:
        if line.strip() == HOSTS_MARKER_START:
            inside = True
            continue
        if line.strip() == HOSTS_MARKER_END:
            inside = False
            continue
        if not inside:
            new_lines.append(line)

    block = build_hosts_block(mock_ip, domains)
    new_lines.append("")
    new_lines.append(block)
    new_content = "\n".join(new_lines) + "\n"

    # Write via tee with sudo
    escaped = new_content.replace("'", "'\\''")
    cmd = f"printf '%s' '{escaped}' | sudo -S tee /etc/hosts > /dev/null"
    stdin, stdout, stderr = client.exec_command(cmd, get_pty=True)
    stdin.write(password + "\n")
    stdin.flush()
    rc = stdout.channel.recv_exit_status()
    if rc != 0:
        err = stderr.read().decode(errors="replace").strip()
        log_fn(f"  ✗ Failed to write /etc/hosts: {err}")
        return False
    log_fn(f"  ✓ /etc/hosts updated ({len(domains)} domains → {mock_ip})")
    return True

def remove_hosts(client, password, log_fn):
    """Remove the traffic-sim block from /etc/hosts."""
    rc, current, err = ssh_run(client, "cat /etc/hosts")
    if rc != 0:
        log_fn(f"  ✗ Could not read /etc/hosts: {err}")
        return False
    lines = current.splitlines()
    new_lines, inside = [], False
    for line in lines:
        if line.strip() == HOSTS_MARKER_START:
            inside = True; continue
        if line.strip() == HOSTS_MARKER_END:
            inside = False; continue
        if not inside:
            new_lines.append(line)
    new_content = "\n".join(new_lines) + "\n"
    escaped = new_content.replace("'", "'\\''")
    cmd = f"printf '%s' '{escaped}' | sudo -S tee /etc/hosts > /dev/null"
    stdin, stdout, stderr = client.exec_command(cmd, get_pty=True)
    stdin.write(password + "\n")
    stdin.flush()
    rc = stdout.channel.recv_exit_status()
    if rc == 0:
        log_fn("  ✓ Traffic-sim entries removed from /etc/hosts")
        return True
    log_fn(f"  ✗ Removal failed: {stderr.read().decode(errors='replace').strip()}")
    return False

def generate_traffic(client, domains, cycles, delay_sec, log_fn):
    """Run curl requests on the remote host for each domain."""
    log_fn(f"  → Starting traffic generation ({cycles} cycles, {delay_sec}s delay)")
    for cycle in range(1, cycles + 1):
        log_fn(f"  ↻ Cycle {cycle}/{cycles}")
        for domain in domains:
            cmd = (
                f"curl -s -o /dev/null -w '%{{http_code}}' "
                f"--max-time 5 --connect-timeout 3 http://{domain}/"
            )
            rc, out, err = ssh_run(client, cmd)
            status = out.strip() if out else "???"
            log_fn(f"    {domain:<30} HTTP {status}")
        if cycle < cycles:
            time.sleep(delay_sec)
    log_fn("  ✓ Traffic generation complete")

# ─── IP range helpers ─────────────────────────────────────────────────────────

def expand_ip_range(range_str):
    """
    Accept CIDR (192.168.1.0/24), dash range (192.168.1.1-20),
    or comma-separated IPs.
    Returns list of IP strings.
    """
    range_str = range_str.strip()
    ips = []
    if "/" in range_str:
        net = ipaddress.ip_network(range_str, strict=False)
        ips = [str(ip) for ip in net.hosts()]
    elif "-" in range_str:
        parts = range_str.rsplit("-", 1)
        base = parts[0].strip()
        base_parts = base.split(".")
        start_ip = ipaddress.ip_address(base)
        last_octet = int(parts[1].strip())
        end_base = ".".join(base_parts[:3])
        for i in range(int(base_parts[3]), last_octet + 1):
            ips.append(f"{end_base}.{i}")
    else:
        ips = [ip.strip() for ip in range_str.split(",") if ip.strip()]
    return ips

# ─── GUI ─────────────────────────────────────────────────────────────────────

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Network Traffic Simulator — Cybersecurity Training")
        self.geometry("960x780")
        self.minsize(800, 650)
        self.configure(bg="#0d1117")
        self.resizable(True, True)

        self._log_queue = queue.Queue()
        self._running   = False
        self._stop_flag = threading.Event()

        self._build_ui()
        self._poll_log()

    # ── UI construction ──────────────────────────────────────────────────────

    def _build_ui(self):
        BG      = "#0d1117"
        PANEL   = "#161b22"
        BORDER  = "#30363d"
        ACCENT  = "#58a6ff"
        GREEN   = "#3fb950"
        RED     = "#f85149"
        YELLOW  = "#d29922"
        FG      = "#e6edf3"
        FG_DIM  = "#8b949e"

        MONO = tkfont.Font(family="Monospace", size=9)
        HEAD = tkfont.Font(family="Sans", size=11, weight="bold")
        BIG  = tkfont.Font(family="Sans", size=14, weight="bold")

        self._colors = dict(BG=BG, PANEL=PANEL, BORDER=BORDER, ACCENT=ACCENT,
                            GREEN=GREEN, RED=RED, YELLOW=YELLOW, FG=FG, FG_DIM=FG_DIM)

        # ── Header ──────────────────────────────────────────────────────────
        hdr = tk.Frame(self, bg="#0d1117", pady=12)
        hdr.pack(fill="x", padx=20)

        tk.Label(hdr, text="⚡  Network Traffic Simulator", font=BIG,
                 bg=BG, fg=ACCENT).pack(side="left")
        tk.Label(hdr, text="Sandboxed Lab Environment", font=("Sans", 9),
                 bg=BG, fg=FG_DIM).pack(side="left", padx=14, pady=2)

        self._status_dot = tk.Label(hdr, text="●", font=("Sans", 14),
                                    bg=BG, fg=FG_DIM)
        self._status_dot.pack(side="right")
        self._status_lbl = tk.Label(hdr, text="Idle", font=("Sans", 9),
                                    bg=BG, fg=FG_DIM)
        self._status_lbl.pack(side="right", padx=4)

        sep = tk.Frame(self, bg=BORDER, height=1)
        sep.pack(fill="x")

        # ── Main split ──────────────────────────────────────────────────────
        main = tk.Frame(self, bg=BG)
        main.pack(fill="both", expand=True, padx=0)

        left  = tk.Frame(main, bg=BG, width=340)
        right = tk.Frame(main, bg=BG)
        left.pack(side="left", fill="y", padx=(16,0), pady=12)
        right.pack(side="left", fill="both", expand=True, padx=16, pady=12)
        left.pack_propagate(False)

        # ─────────── LEFT PANEL ─────────────────────────────────────────────

        def section(parent, title):
            f = tk.LabelFrame(parent, text=f"  {title}  ", font=("Sans", 9, "bold"),
                              bg=PANEL, fg=ACCENT, bd=1, relief="solid",
                              highlightbackground=BORDER)
            f.pack(fill="x", pady=(0, 10))
            return f

        def row(parent, label, widget_fn, **kw):
            r = tk.Frame(parent, bg=PANEL)
            r.pack(fill="x", padx=10, pady=4)
            tk.Label(r, text=label, width=16, anchor="w", font=("Sans", 9),
                     bg=PANEL, fg=FG_DIM).pack(side="left")
            w = widget_fn(r, **kw)
            w.pack(side="left", fill="x", expand=True)
            return w

        def entry(parent, textvariable=None, show=None):
            e = tk.Entry(parent, bg="#21262d", fg=FG, relief="flat",
                         insertbackground=ACCENT, bd=4,
                         textvariable=textvariable, show=show,
                         font=("Monospace", 9))
            return e

        # — SSH credentials —
        sec1 = section(left, "SSH Credentials")
        self._v_user = tk.StringVar(value="root")
        self._v_pass = tk.StringVar()
        row(sec1, "Username", entry, textvariable=self._v_user)
        row(sec1, "Password", entry, textvariable=self._v_pass, show="•")

        # — Target hosts —
        sec2 = section(left, "Target Hosts (IP Range)")
        range_frame = tk.Frame(sec2, bg=PANEL)
        range_frame.pack(fill="x", padx=10, pady=4)
        tk.Label(range_frame, text="IP Range / CIDR", font=("Sans", 9),
                 bg=PANEL, fg=FG_DIM).pack(anchor="w")
        self._v_range = tk.StringVar(value="192.168.1.1-10")
        tk.Entry(range_frame, bg="#21262d", fg=FG, relief="flat", bd=4,
                 textvariable=self._v_range, insertbackground=ACCENT,
                 font=("Monospace", 9)).pack(fill="x", pady=(2,0))
        tk.Label(range_frame,
                 text="Examples: 192.168.1.0/24 | 10.0.0.1-50 | 10.0.0.1,10.0.0.5",
                 font=("Sans", 7), bg=PANEL, fg=FG_DIM).pack(anchor="w", pady=(2,4))

        # — Mock server —
        sec3 = section(left, "Mock Server")
        self._v_mock_ip = tk.StringVar(value="192.168.1.254")
        row(sec3, "Mock Server IP", entry, textvariable=self._v_mock_ip)
        tk.Label(sec3,
                 text="  Run mock_server.py on this host first.",
                 font=("Sans", 7, "italic"), bg=PANEL, fg=FG_DIM).pack(anchor="w", padx=10, pady=(0,6))

        # — Traffic options —
        sec4 = section(left, "Traffic Options")
        self._v_cycles  = tk.IntVar(value=3)
        self._v_delay   = tk.DoubleVar(value=2.0)
        self._v_threads = tk.IntVar(value=5)

        def spin(parent, textvariable, from_, to, increment=1):
            s = tk.Spinbox(parent, from_=from_, to=to, textvariable=textvariable,
                           increment=increment, width=6,
                           bg="#21262d", fg=FG, relief="flat", bd=4,
                           buttonbackground="#21262d", insertbackground=ACCENT,
                           font=("Monospace", 9))
            return s

        row(sec4, "Cycles / host",   spin, textvariable=self._v_cycles,  from_=1, to=100)
        row(sec4, "Delay (sec)",     spin, textvariable=self._v_delay,   from_=0.5, to=60, increment=0.5)
        row(sec4, "Threads",         spin, textvariable=self._v_threads, from_=1, to=20)

        # — Domain selector —
        sec5 = section(left, "Domains")
        self._domain_vars = {}
        dom_scroll = tk.Frame(sec5, bg=PANEL)
        dom_scroll.pack(fill="x", padx=10, pady=4)
        for d in TOP_20_DOMAINS:
            v = tk.BooleanVar(value=True)
            self._domain_vars[d] = v
            cb = tk.Checkbutton(dom_scroll, text=d, variable=v,
                                bg=PANEL, fg=FG, selectcolor="#21262d",
                                activebackground=PANEL, activeforeground=ACCENT,
                                font=("Monospace", 8), anchor="w")
            cb.pack(fill="x")

        btn_row = tk.Frame(sec5, bg=PANEL)
        btn_row.pack(fill="x", padx=10, pady=(2, 8))
        tk.Button(btn_row, text="All", width=5,
                  bg="#21262d", fg=FG, relief="flat", bd=0, padx=4,
                  command=lambda: [v.set(True) for v in self._domain_vars.values()]).pack(side="left")
        tk.Button(btn_row, text="None", width=5,
                  bg="#21262d", fg=FG, relief="flat", bd=0, padx=4,
                  command=lambda: [v.set(False) for v in self._domain_vars.values()]).pack(side="left", padx=6)

        # ─────────── RIGHT PANEL ────────────────────────────────────────────

        # Action buttons
        btn_frame = tk.Frame(right, bg=BG)
        btn_frame.pack(fill="x", pady=(0, 10))

        def action_btn(parent, text, color, cmd):
            b = tk.Button(parent, text=text, command=cmd,
                          bg=color, fg="#0d1117", relief="flat", bd=0,
                          font=("Sans", 10, "bold"), padx=18, pady=8,
                          cursor="hand2", activebackground=color)
            b.pack(side="left", padx=(0, 8))
            return b

        self._btn_deploy   = action_btn(btn_frame, "▶  Deploy & Run",  GREEN,  self._do_deploy)
        self._btn_hosts    = action_btn(btn_frame, "⚙  Hosts Only",    YELLOW, self._do_hosts_only)
        self._btn_remove   = action_btn(btn_frame, "✕  Remove Hosts",  RED,    self._do_remove)
        self._btn_stop     = action_btn(btn_frame, "■  Stop",          "#8b949e", self._do_stop)
        self._btn_stop.config(state="disabled")

        tk.Button(btn_frame, text="⊘  Clear Log",
                  command=self._clear_log,
                  bg=PANEL, fg=FG_DIM, relief="flat", bd=0,
                  font=("Sans", 9), padx=12, pady=8,
                  cursor="hand2").pack(side="right")

        # Progress bar
        prog_frame = tk.Frame(right, bg=BG)
        prog_frame.pack(fill="x", pady=(0, 8))
        self._progress = ttk.Progressbar(prog_frame, mode="indeterminate", length=200)
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TProgressbar", troughcolor=PANEL, background=ACCENT,
                        bordercolor=BORDER, lightcolor=ACCENT, darkcolor=ACCENT)
        self._progress.pack(fill="x")

        # Host status table
        table_lbl = tk.Label(right, text="HOST STATUS", font=("Sans", 8, "bold"),
                             bg=BG, fg=FG_DIM, anchor="w")
        table_lbl.pack(fill="x")

        table_frame = tk.Frame(right, bg=PANEL, bd=1, relief="solid",
                               highlightbackground=BORDER)
        table_frame.pack(fill="x", pady=(2, 10))

        cols = ("IP Address", "Hosts File", "Traffic", "Last Seen")
        self._tree = ttk.Treeview(table_frame, columns=cols, show="headings",
                                  height=6, style="Custom.Treeview")
        style.configure("Custom.Treeview",
                        background=PANEL, foreground=FG,
                        rowheight=22, fieldbackground=PANEL,
                        bordercolor=BORDER, borderwidth=0)
        style.configure("Custom.Treeview.Heading",
                        background="#21262d", foreground=FG_DIM,
                        relief="flat", font=("Sans", 8))
        style.map("Custom.Treeview", background=[("selected", "#1f2937")])

        col_widths = {"IP Address": 130, "Hosts File": 100, "Traffic": 100, "Last Seen": 160}
        for c in cols:
            self._tree.heading(c, text=c)
            self._tree.column(c, width=col_widths[c], anchor="center")
        self._tree.pack(fill="x")

        self._tree.tag_configure("ok",      foreground=GREEN)
        self._tree.tag_configure("fail",    foreground=RED)
        self._tree.tag_configure("pending", foreground=YELLOW)
        self._tree.tag_configure("idle",    foreground=FG_DIM)

        self._host_rows = {}

        # Log
        log_lbl = tk.Label(right, text="ACTIVITY LOG", font=("Sans", 8, "bold"),
                           bg=BG, fg=FG_DIM, anchor="w")
        log_lbl.pack(fill="x")

        self._log = scrolledtext.ScrolledText(
            right, bg=PANEL, fg=FG, font=MONO, relief="flat",
            insertbackground=ACCENT, state="disabled", wrap="word")
        self._log.pack(fill="both", expand=True)

        self._log.tag_configure("ok",      foreground=GREEN)
        self._log.tag_configure("fail",    foreground=RED)
        self._log.tag_configure("warn",    foreground=YELLOW)
        self._log.tag_configure("info",    foreground=ACCENT)
        self._log.tag_configure("dim",     foreground=FG_DIM)
        self._log.tag_configure("default", foreground=FG)

    # ── Logging ──────────────────────────────────────────────────────────────

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
        except queue.Empty:
            pass
        self.after(100, self._poll_log)

    def _clear_log(self):
        self._log.configure(state="normal")
        self._log.delete("1.0", "end")
        self._log.configure(state="disabled")

    # ── Host table ───────────────────────────────────────────────────────────

    def _init_table(self, ips):
        for item in self._tree.get_children():
            self._tree.delete(item)
        self._host_rows = {}
        for ip in ips:
            iid = self._tree.insert("", "end",
                                    values=(ip, "—", "—", "—"),
                                    tags=("idle",))
            self._host_rows[ip] = iid

    def _update_row(self, ip, hosts_status=None, traffic_status=None, last_seen=None, tag="idle"):
        iid = self._host_rows.get(ip)
        if not iid:
            return
        cur = self._tree.item(iid, "values")
        new = list(cur)
        if hosts_status  is not None: new[1] = hosts_status
        if traffic_status is not None: new[2] = traffic_status
        if last_seen     is not None: new[3] = last_seen
        self._tree.item(iid, values=new, tags=(tag,))

    # ── Validation ───────────────────────────────────────────────────────────

    def _validate(self):
        if not self._v_user.get().strip():
            messagebox.showerror("Validation", "SSH username is required.")
            return None
        if not self._v_pass.get():
            messagebox.showerror("Validation", "SSH password is required.")
            return None
        if not self._v_mock_ip.get().strip():
            messagebox.showerror("Validation", "Mock server IP is required.")
            return None
        try:
            ips = expand_ip_range(self._v_range.get())
        except Exception as e:
            messagebox.showerror("Validation", f"Invalid IP range: {e}")
            return None
        if not ips:
            messagebox.showerror("Validation", "IP range produced no addresses.")
            return None
        domains = [d for d, v in self._domain_vars.items() if v.get()]
        if not domains:
            messagebox.showerror("Validation", "Select at least one domain.")
            return None
        return ips, domains

    # ── Actions ──────────────────────────────────────────────────────────────

    def _set_running(self, running):
        self._running = running
        state_action = "disabled" if running else "normal"
        state_stop   = "normal"  if running else "disabled"
        self._btn_deploy.config(state=state_action)
        self._btn_hosts.config(state=state_action)
        self._btn_remove.config(state=state_action)
        self._btn_stop.config(state=state_stop)
        if running:
            self._progress.start(12)
            self._status_dot.config(fg="#3fb950")
            self._status_lbl.config(text="Running")
        else:
            self._progress.stop()
            self._progress["value"] = 0
            self._status_dot.config(fg="#8b949e")
            self._status_lbl.config(text="Idle")

    def _do_stop(self):
        self._stop_flag.set()
        self._log_msg("Stop requested — finishing current host…", "warn")

    def _do_deploy(self):
        result = self._validate()
        if not result:
            return
        ips, domains = result
        self._init_table(ips)
        self._stop_flag.clear()
        self._set_running(True)
        threading.Thread(target=self._worker_deploy,
                         args=(ips, domains, True),
                         daemon=True).start()

    def _do_hosts_only(self):
        result = self._validate()
        if not result:
            return
        ips, domains = result
        self._init_table(ips)
        self._stop_flag.clear()
        self._set_running(True)
        threading.Thread(target=self._worker_deploy,
                         args=(ips, domains, False),
                         daemon=True).start()

    def _do_remove(self):
        result = self._validate()
        if not result:
            return
        ips, _ = result
        self._init_table(ips)
        self._stop_flag.clear()
        self._set_running(True)
        threading.Thread(target=self._worker_remove,
                         args=(ips,),
                         daemon=True).start()

    # ── Workers (run in threads) ──────────────────────────────────────────────

    def _worker_deploy(self, ips, domains, run_traffic):
        user      = self._v_user.get().strip()
        password  = self._v_pass.get()
        mock_ip   = self._v_mock_ip.get().strip()
        cycles    = self._v_cycles.get()
        delay     = self._v_delay.get()
        max_thr   = self._v_threads.get()
        sem       = threading.Semaphore(max_thr)

        self._log_msg(f"Starting deployment → {len(ips)} hosts, {len(domains)} domains", "info")
        self._log_msg(f"Mock server: {mock_ip}   Cycles: {cycles}   Threads: {max_thr}", "dim")

        def handle(ip):
            if self._stop_flag.is_set():
                return
            with sem:
                self._update_row(ip, hosts_status="Connecting…", tag="pending")
                log = lambda m: self._log_msg(f"[{ip}] {m}")
                try:
                    client = ssh_connect(ip, user, password)
                except Exception as e:
                    self._log_msg(f"[{ip}] ✗ SSH failed: {e}", "fail")
                    self._update_row(ip, hosts_status="SSH fail", tag="fail")
                    return
                try:
                    ok = inject_hosts(client, mock_ip, domains, password, log)
                    h_status = "✓ Updated" if ok else "✗ Failed"
                    h_tag    = "ok" if ok else "fail"
                    self._update_row(ip, hosts_status=h_status, tag=h_tag)

                    if ok and run_traffic and not self._stop_flag.is_set():
                        self._update_row(ip, traffic_status="Running…", tag="pending")
                        generate_traffic(client, domains, cycles, delay, log)
                        ts = time.strftime("%H:%M:%S")
                        self._update_row(ip, traffic_status="✓ Done",
                                         last_seen=ts, tag="ok")
                    elif not run_traffic and ok:
                        self._update_row(ip, traffic_status="—", tag="ok")
                finally:
                    client.close()

        threads = [threading.Thread(target=handle, args=(ip,), daemon=True) for ip in ips]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        if self._stop_flag.is_set():
            self._log_msg("Stopped by user.", "warn")
        else:
            self._log_msg("All hosts processed.", "ok")
        self.after(0, lambda: self._set_running(False))

    def _worker_remove(self, ips):
        user     = self._v_user.get().strip()
        password = self._v_pass.get()
        max_thr  = self._v_threads.get()
        sem      = threading.Semaphore(max_thr)

        self._log_msg(f"Removing traffic-sim entries from {len(ips)} hosts…", "warn")

        def handle(ip):
            with sem:
                self._update_row(ip, hosts_status="Connecting…", tag="pending")
                log = lambda m: self._log_msg(f"[{ip}] {m}")
                try:
                    client = ssh_connect(ip, user, password)
                except Exception as e:
                    self._log_msg(f"[{ip}] ✗ SSH failed: {e}", "fail")
                    self._update_row(ip, hosts_status="SSH fail", tag="fail")
                    return
                try:
                    ok = remove_hosts(client, password, log)
                    self._update_row(ip, hosts_status="✓ Cleaned" if ok else "✗ Failed",
                                     traffic_status="—", tag="ok" if ok else "fail")
                finally:
                    client.close()

        threads = [threading.Thread(target=handle, args=(ip,), daemon=True) for ip in ips]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self._log_msg("Removal complete.", "ok")
        self.after(0, lambda: self._set_running(False))


# ─── Entry point ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    app = App()
    app.mainloop()
