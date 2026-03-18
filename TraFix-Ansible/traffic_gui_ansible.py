#!/usr/bin/env python3
"""
traffic_gui_ansible.py — Network Traffic Simulator GUI (Ansible Edition)
Sandboxed cybersecurity training environment tool.

Uses ansible-playbook as a subprocess — no paramiko, no manual SSH handling.
Supports two host config modes:
  - DNS mode:   manages dnsmasq on the control node, targets point resolv.conf here
  - Hosts mode: Ansible pushes /etc/hosts entries to each target directly

Requirements:
    ansible (installed and on PATH)
    python3-tk

Usage:
    python3 traffic_gui_ansible.py
    (DNS mode may need sudo for dnsmasq; hosts mode needs ansible become/sudo on targets)
"""

import json
import os
import queue
import shutil
import subprocess
import tempfile
import threading
import time
import tkinter as tk
from tkinter import filedialog, font as tkfont, messagebox, scrolledtext, ttk

# ── Constants ──────────────────────────────────────────────────────────────────

TOP_20_DOMAINS = [
    "google.com", "youtube.com", "facebook.com", "amazon.com",
    "wikipedia.org", "twitter.com", "x.com", "reddit.com",
    "instagram.com", "linkedin.com", "netflix.com", "bing.com",
    "microsoft.com", "apple.com", "espn.com", "cnn.com",
    "nytimes.com", "twitch.tv", "ebay.com", "yahoo.com", "zoom.us",
]

DNSMASQ_CONF_PATH  = "/etc/dnsmasq.d/traffic-sim.conf"
HOSTS_MARKER_START = "# === TRAFFIC-SIM START ==="
HOSTS_MARKER_END   = "# === TRAFFIC-SIM END ==="

PLAYBOOK_DIR = os.path.expanduser("~/.traffic-sim/playbooks")
os.makedirs(PLAYBOOK_DIR, exist_ok=True)

# ── Ansible helpers ────────────────────────────────────────────────────────────

def ansible_available():
    return shutil.which("ansible-playbook") is not None

def ansible_ping(inventory, limit, ask_pass, ask_become_pass):
    """Run ansible ping against hosts to verify connectivity."""
    cmd = ["ansible", "-i", inventory, limit or "all", "-m", "ping"]
    if ask_pass:
        cmd.append("--ask-pass")
    if ask_become_pass:
        cmd.append("--ask-become-pass")
    return cmd

def run_playbook(playbook_path, inventory, limit=None,
                 extra_vars=None, ask_pass=False, ask_become_pass=False,
                 vault_password_file=None, log_fn=None, stop_flag=None):
    """
    Run an ansible-playbook command, streaming output line by line.
    Returns exit code.
    """
    cmd = ["ansible-playbook", "-i", inventory, playbook_path]
    if limit:
        cmd += ["--limit", limit]
    if extra_vars:
        cmd += ["--extra-vars", json.dumps(extra_vars)]
    if ask_pass:
        cmd.append("--ask-pass")
    if ask_become_pass:
        cmd.append("--ask-become-pass")
    if vault_password_file:
        cmd += ["--vault-password-file", vault_password_file]

    if log_fn:
        log_fn(f"  $ {' '.join(cmd)}", "dim")

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        for line in proc.stdout:
            line = line.rstrip()
            if not line:
                continue
            if stop_flag and stop_flag.is_set():
                proc.terminate()
                if log_fn:
                    log_fn("  Playbook terminated by user.", "warn")
                break
            if log_fn:
                # Colour ansible output meaningfully
                tag = "default"
                l = line.lower()
                if "ok:" in l or "changed:" in l:
                    tag = "ok"
                elif "failed:" in l or "error" in l or "unreachable" in l:
                    tag = "fail"
                elif "skipping:" in l or "warning" in l:
                    tag = "warn"
                elif "play recap" in l or "task [" in l or "play [" in l:
                    tag = "info"
                log_fn(f"  {line}", tag)
        proc.wait()
        return proc.returncode
    except FileNotFoundError:
        if log_fn:
            log_fn("  ansible-playbook not found on PATH.", "fail")
        return 1
    except Exception as e:
        if log_fn:
            log_fn(f"  Error running playbook: {e}", "fail")
        return 1

# ── Playbook generators ────────────────────────────────────────────────────────

def write_playbook(name, content):
    path = os.path.join(PLAYBOOK_DIR, name)
    with open(path, "w") as f:
        f.write(content)
    return path

def playbook_hosts_file(mock_ip, domains):
    """Playbook: push /etc/hosts entries to targets using lineinfile/blockinfile."""
    block_lines = "\n".join(
        f"  {mock_ip}  {d} www.{d}" for d in domains
    )
    return write_playbook("deploy_hosts.yml", f"""---
- name: Traffic Sim — Deploy /etc/hosts entries
  hosts: all
  become: yes
  tasks:

    - name: Remove old traffic-sim block
      ansible.builtin.lineinfile:
        path: /etc/hosts
        state: absent
        regexp: "traffic-sim"

    - name: Remove marker lines
      ansible.builtin.lineinfile:
        path: /etc/hosts
        state: absent
        line: "{{{{ item }}}}"
      loop:
        - "{HOSTS_MARKER_START}"
        - "{HOSTS_MARKER_END}"

    - name: Insert traffic-sim block
      ansible.builtin.blockinfile:
        path: /etc/hosts
        marker: "# {{{{ ANSIBLE_MANAGED_BLOCK }}}} traffic-sim"
        block: |
{block_lines}
        insertafter: EOF
        create: yes

    - name: Confirm entries present
      ansible.builtin.command: grep -c "{mock_ip}" /etc/hosts
      register: grep_result
      changed_when: false

    - name: Report
      ansible.builtin.debug:
        msg: "hosts file updated — {{{{ grep_result.stdout }}}} entries for {mock_ip}"
""")

def playbook_remove_hosts():
    """Playbook: remove traffic-sim block from /etc/hosts on targets."""
    return write_playbook("remove_hosts.yml", f"""---
- name: Traffic Sim — Remove /etc/hosts entries
  hosts: all
  become: yes
  tasks:

    - name: Remove traffic-sim blockinfile block
      ansible.builtin.blockinfile:
        path: /etc/hosts
        marker: "# {{{{ ANSIBLE_MANAGED_BLOCK }}}} traffic-sim"
        state: absent

    - name: Remove any stray marker lines
      ansible.builtin.lineinfile:
        path: /etc/hosts
        state: absent
        regexp: "traffic-sim|TRAFFIC-SIM"

    - name: Confirm clean
      ansible.builtin.command: grep -c "traffic-sim" /etc/hosts
      register: check
      failed_when: false
      changed_when: false

    - name: Report
      ansible.builtin.debug:
        msg: "hosts file clean ({{{{ check.stdout }}}} traffic-sim lines remaining)"
""")

def playbook_generate_traffic(domains, cycles, delay_sec):
    """Playbook: run curl against each domain from the target hosts."""
    domain_list = "\n".join(f'        - "{d}"' for d in domains)
    return write_playbook("generate_traffic.yml", f"""---
- name: Traffic Sim — Generate HTTP traffic
  hosts: all
  gather_facts: no
  vars:
    domains:
{domain_list}
    cycles: {cycles}
    delay_between_cycles: {delay_sec}

  tasks:

    - name: Verify curl is available
      ansible.builtin.command: which curl
      changed_when: false
      register: curl_check
      failed_when: curl_check.rc != 0

    - name: Generate traffic — cycle loop
      ansible.builtin.shell: |
        for domain in {{{{ domains | join(' ') }}}}; do
          code=$(curl -s -o /dev/null -w "%{{http_code}}" \\
                 --max-time 5 --connect-timeout 3 \\
                 "http://$domain/")
          echo "$domain -> HTTP $code"
        done
      loop: "{{{{ range(cycles | int) | list }}}}"
      loop_control:
        label: "Cycle {{{{ item + 1 }}}} of {{{{ cycles }}}}"
      register: curl_results

    - name: Show traffic results
      ansible.builtin.debug:
        msg: "{{{{ item.stdout_lines }}}}"
      loop: "{{{{ curl_results.results }}}}"
      loop_control:
        label: "Cycle results"
""")

def playbook_set_dns(server_ip):
    """Playbook: set /etc/resolv.conf on targets to point at our DNS server."""
    return write_playbook("set_dns.yml", f"""---
- name: Traffic Sim — Configure DNS on targets
  hosts: all
  become: yes
  tasks:

    - name: Disable systemd-resolved if present
      ansible.builtin.systemd:
        name: systemd-resolved
        state: stopped
        enabled: no
      ignore_errors: yes

    - name: Remove existing resolv.conf (may be a symlink)
      ansible.builtin.file:
        path: /etc/resolv.conf
        state: absent

    - name: Write new resolv.conf pointing at traffic-sim DNS
      ansible.builtin.copy:
        dest: /etc/resolv.conf
        content: |
          # Managed by traffic-sim — points at lab DNS server
          nameserver {server_ip}
        owner: root
        group: root
        mode: '0644'

    - name: Verify DNS resolution works
      ansible.builtin.command: dig +short google.com @{server_ip}
      register: dig_result
      changed_when: false
      ignore_errors: yes

    - name: DNS check result
      ansible.builtin.debug:
        msg: "DNS check for google.com → {{{{ dig_result.stdout | default('no response') }}}}"
""")

def playbook_restore_dns():
    """Playbook: restore systemd-resolved and default resolv.conf on targets."""
    return write_playbook("restore_dns.yml", f"""---
- name: Traffic Sim — Restore DNS on targets
  hosts: all
  become: yes
  tasks:

    - name: Remove traffic-sim resolv.conf
      ansible.builtin.file:
        path: /etc/resolv.conf
        state: absent

    - name: Re-enable systemd-resolved
      ansible.builtin.systemd:
        name: systemd-resolved
        state: started
        enabled: yes
      ignore_errors: yes

    - name: Restore symlink for resolved
      ansible.builtin.file:
        src: /run/systemd/resolve/stub-resolv.conf
        dest: /etc/resolv.conf
        state: link
        force: yes
      ignore_errors: yes

    - name: Confirm
      ansible.builtin.debug:
        msg: "DNS restored to systemd-resolved on {{{{ inventory_hostname }}}}"
""")

# ── dnsmasq helpers (local, DNS mode only) ─────────────────────────────────────

def write_dnsmasq_conf(mock_ip, domains):
    lines = ["# traffic-sim — managed by traffic_gui_ansible.py\n"]
    for d in domains:
        lines.append(f"address=/{d}/{mock_ip}\n")
        lines.append(f"address=/www.{d}/{mock_ip}\n")
    os.makedirs(os.path.dirname(DNSMASQ_CONF_PATH), exist_ok=True)
    with open(DNSMASQ_CONF_PATH, "w") as f:
        f.writelines(lines)

def remove_dnsmasq_conf():
    if os.path.exists(DNSMASQ_CONF_PATH):
        os.remove(DNSMASQ_CONF_PATH)

def restart_dnsmasq():
    r = subprocess.run(["sudo", "systemctl", "restart", "dnsmasq"],
                       capture_output=True, text=True, timeout=15)
    return r.returncode == 0, (r.stdout + r.stderr).strip()

def dnsmasq_status():
    r = subprocess.run(["systemctl", "is-active", "dnsmasq"],
                       capture_output=True, text=True, timeout=5)
    active = r.stdout.strip() == "active"
    return active, r.stdout.strip()

# ── GUI ────────────────────────────────────────────────────────────────────────

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Network Traffic Simulator — Ansible Edition")
        self.geometry("1060x860")
        self.minsize(900, 700)
        self.configure(bg="#0d1117")
        self.resizable(True, True)

        self._log_queue = queue.Queue()
        self._stop_flag = threading.Event()
        self._running   = False

        self._build_ui()
        self._poll_log()
        self._check_ansible()

    # ── UI ─────────────────────────────────────────────────────────────────────

    def _build_ui(self):
        BG, PANEL, BORDER = "#0d1117", "#161b22", "#30363d"
        ACCENT, GREEN, RED, YELLOW = "#58a6ff", "#3fb950", "#f85149", "#d29922"
        FG, DIM = "#e6edf3", "#8b949e"
        MONO = tkfont.Font(family="Monospace", size=9)

        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TProgressbar", troughcolor=PANEL, background=ACCENT,
                        bordercolor=BORDER, lightcolor=ACCENT, darkcolor=ACCENT)
        style.configure("Custom.Treeview", background=PANEL, foreground=FG,
                        rowheight=22, fieldbackground=PANEL, borderwidth=0)
        style.configure("Custom.Treeview.Heading", background="#21262d",
                        foreground=DIM, relief="flat", font=("Sans", 8))

        self._c = dict(BG=BG, PANEL=PANEL, BORDER=BORDER, ACCENT=ACCENT,
                       GREEN=GREEN, RED=RED, YELLOW=YELLOW, FG=FG, DIM=DIM)

        # ── Header ─────────────────────────────────────────────────────────────
        hdr = tk.Frame(self, bg=BG, pady=10)
        hdr.pack(fill="x", padx=20)
        tk.Label(hdr, text="⚡  Network Traffic Simulator",
                 font=("Sans", 14, "bold"), bg=BG, fg=ACCENT).pack(side="left")
        tk.Label(hdr, text="Ansible Edition · Sandboxed Lab",
                 font=("Sans", 9), bg=BG, fg=DIM).pack(side="left", padx=12)

        # Status pills (top right)
        pill_frame = tk.Frame(hdr, bg=BG)
        pill_frame.pack(side="right")

        def pill(parent, label):
            f = tk.Frame(parent, bg=PANEL, bd=1, relief="solid",
                         highlightbackground=BORDER)
            f.pack(side="left", padx=3)
            dot = tk.Label(f, text="●", font=("Sans", 10), bg=PANEL, fg=DIM, padx=5)
            dot.pack(side="left")
            lbl = tk.Label(f, text=label, font=("Sans", 9), bg=PANEL, fg=DIM, padx=5)
            lbl.pack(side="left")
            return dot, lbl

        self._ansible_dot, self._ansible_lbl = pill(pill_frame, "ansible")
        self._dns_dot,     self._dns_lbl     = pill(pill_frame, "dnsmasq")

        tk.Frame(self, bg=BORDER, height=1).pack(fill="x")

        # ── Body ───────────────────────────────────────────────────────────────
        body = tk.Frame(self, bg=BG)
        body.pack(fill="both", expand=True)

        left  = tk.Frame(body, bg=BG, width=340)
        right = tk.Frame(body, bg=BG)
        left.pack(side="left", fill="y", padx=(14, 0), pady=12)
        right.pack(side="left", fill="both", expand=True, padx=14, pady=12)
        left.pack_propagate(False)

        # ── Helpers ────────────────────────────────────────────────────────────
        def section(parent, title):
            f = tk.LabelFrame(parent, text=f"  {title}  ",
                              font=("Sans", 9, "bold"), bg=PANEL, fg=ACCENT,
                              bd=1, relief="solid", highlightbackground=BORDER)
            f.pack(fill="x", pady=(0, 8))
            return f

        def field(parent, label, var, show=None, hint=None, browse=None):
            r = tk.Frame(parent, bg=PANEL)
            r.pack(fill="x", padx=10, pady=3)
            tk.Label(r, text=label, width=16, anchor="w",
                     font=("Sans", 9), bg=PANEL, fg=DIM).pack(side="left")
            e = tk.Entry(r, bg="#21262d", fg=FG, relief="flat", bd=4,
                         textvariable=var, show=show,
                         insertbackground=ACCENT, font=("Monospace", 9))
            e.pack(side="left", fill="x", expand=True)
            if browse:
                tk.Button(r, text="…", bg="#21262d", fg=DIM, relief="flat",
                          bd=0, padx=6, command=browse,
                          cursor="hand2").pack(side="left", padx=(4, 0))
            if hint:
                tk.Label(parent, text=hint, font=("Sans", 7),
                         bg=PANEL, fg=DIM).pack(anchor="w", padx=10, pady=(0, 2))
            return e

        def spin(parent, label, var, from_, to, inc=1):
            r = tk.Frame(parent, bg=PANEL)
            r.pack(fill="x", padx=10, pady=3)
            tk.Label(r, text=label, width=16, anchor="w",
                     font=("Sans", 9), bg=PANEL, fg=DIM).pack(side="left")
            tk.Spinbox(r, from_=from_, to=to, textvariable=var, increment=inc,
                       width=7, bg="#21262d", fg=FG, relief="flat", bd=4,
                       buttonbackground="#21262d", insertbackground=ACCENT,
                       font=("Monospace", 9)).pack(side="left")

        def btn_row_frame(parent):
            f = tk.Frame(parent, bg=PANEL)
            f.pack(fill="x", padx=10, pady=(2, 8))
            return f

        def small_btn(parent, text, color, cmd, fg="#0d1117"):
            b = tk.Button(parent, text=text, command=cmd, bg=color, fg=fg,
                          relief="flat", bd=0, font=("Sans", 9, "bold"),
                          padx=10, pady=5, cursor="hand2", activebackground=color)
            b.pack(side="left", padx=(0, 6))
            return b

        # ── LEFT: Ansible settings ──────────────────────────────────────────────
        s_ansible = section(left, "Ansible")

        self._v_inventory   = tk.StringVar(value="/etc/ansible/hosts")
        self._v_limit       = tk.StringVar(value="all")
        self._v_vault_file  = tk.StringVar()
        self._v_ask_pass    = tk.BooleanVar(value=False)
        self._v_ask_become  = tk.BooleanVar(value=False)

        def browse_inventory():
            p = filedialog.askopenfilename(title="Select Ansible inventory",
                                           filetypes=[("All files", "*"), ("INI", "*.ini"), ("YAML", "*.yml")])
            if p:
                self._v_inventory.set(p)

        def browse_vault():
            p = filedialog.askopenfilename(title="Select vault password file")
            if p:
                self._v_vault_file.set(p)

        field(s_ansible, "Inventory file", self._v_inventory,
              browse=browse_inventory,
              hint="  Path to your existing Ansible inventory")
        field(s_ansible, "Limit (hosts)", self._v_limit,
              hint="  e.g. all | webservers | 192.168.1.10")
        field(s_ansible, "Vault pass file", self._v_vault_file,
              browse=browse_vault,
              hint="  Leave blank if not using vault")

        cb_frame = tk.Frame(s_ansible, bg=PANEL)
        cb_frame.pack(fill="x", padx=10, pady=(2, 4))
        tk.Checkbutton(cb_frame, text="--ask-pass (SSH password prompt)",
                       variable=self._v_ask_pass,
                       bg=PANEL, fg=FG, selectcolor="#21262d",
                       activebackground=PANEL, font=("Sans", 8)).pack(anchor="w")
        tk.Checkbutton(cb_frame, text="--ask-become-pass (sudo password prompt)",
                       variable=self._v_ask_become,
                       bg=PANEL, fg=FG, selectcolor="#21262d",
                       activebackground=PANEL, font=("Sans", 8)).pack(anchor="w")

        ping_row = btn_row_frame(s_ansible)
        small_btn(ping_row, "⚡ Test Connectivity", ACCENT, self._do_ping, fg="#0d1117")

        # Playbook output path info
        tk.Label(s_ansible,
                 text=f"  Playbooks written to: {PLAYBOOK_DIR}",
                 font=("Sans", 7, "italic"), bg=PANEL, fg=DIM).pack(anchor="w", padx=10, pady=(0, 6))

        # ── LEFT: Host config mode ──────────────────────────────────────────────
        s_mode = section(left, "Host Config Mode")

        self._v_mode = tk.StringVar(value="dns")
        mode_frame = tk.Frame(s_mode, bg=PANEL)
        mode_frame.pack(fill="x", padx=10, pady=6)

        tk.Radiobutton(mode_frame, text="DNS (dnsmasq on control node)",
                       variable=self._v_mode, value="dns",
                       bg=PANEL, fg=FG, selectcolor="#21262d",
                       activebackground=PANEL, font=("Sans", 9),
                       command=self._toggle_mode).pack(anchor="w")
        tk.Label(mode_frame,
                 text="  Targets point resolv.conf here. One change, all hosts.",
                 font=("Sans", 7, "italic"), bg=PANEL, fg=DIM).pack(anchor="w", padx=18)

        tk.Frame(mode_frame, bg=BORDER, height=1).pack(fill="x", pady=6)

        tk.Radiobutton(mode_frame, text="/etc/hosts (Ansible pushes to each target)",
                       variable=self._v_mode, value="hosts",
                       bg=PANEL, fg=FG, selectcolor="#21262d",
                       activebackground=PANEL, font=("Sans", 9),
                       command=self._toggle_mode).pack(anchor="w")
        tk.Label(mode_frame,
                 text="  Ansible blockinfile — no SSH creds needed in the GUI.",
                 font=("Sans", 7, "italic"), bg=PANEL, fg=DIM).pack(anchor="w", padx=18)

        # ── LEFT: DNS mode panel ────────────────────────────────────────────────
        self._dns_panel = section(left, "DNS Mode — Control Node")

        self._v_server_ip = tk.StringVar(value="192.168.1.254")
        field(self._dns_panel, "This node's IP", self._v_server_ip,
              hint="  Targets must resolve DNS via this IP")

        dns_btns = btn_row_frame(self._dns_panel)
        small_btn(dns_btns, "⚙ Apply DNS",  GREEN,  self._do_apply_dns)
        small_btn(dns_btns, "✕ Clear DNS",  RED,    self._do_clear_dns)
        small_btn(dns_btns, "↺ Restart",    YELLOW, self._do_restart_dnsmasq)

        dns_target_btns = btn_row_frame(self._dns_panel)
        small_btn(dns_target_btns, "→ Push resolv.conf via Ansible", ACCENT,
                  self._do_push_resolv, fg="#0d1117")
        small_btn(dns_target_btns, "↩ Restore DNS", "#30363d",
                  self._do_restore_dns, fg=FG)

        tk.Label(self._dns_panel,
                 text="  Push resolv.conf uses Ansible to set nameserver on all targets.",
                 font=("Sans", 7, "italic"), bg=PANEL, fg=DIM).pack(anchor="w", padx=10, pady=(0, 6))

        # ── LEFT: Hosts mode panel ──────────────────────────────────────────────
        self._hosts_panel = section(left, "Hosts Mode — Mock Server IP")

        self._v_mock_ip = tk.StringVar(value="192.168.1.254")
        field(self._hosts_panel, "Mock server IP", self._v_mock_ip,
              hint="  IP inserted into /etc/hosts on each target")

        hosts_btns = btn_row_frame(self._hosts_panel)
        small_btn(hosts_btns, "⚙ Deploy Hosts",   GREEN,  self._do_deploy_hosts)
        small_btn(hosts_btns, "✕ Remove Hosts",   RED,    self._do_remove_hosts)

        self._hosts_panel.pack_forget()  # hidden until hosts mode selected

        # ── LEFT: Traffic ───────────────────────────────────────────────────────
        s_traffic = section(left, "Traffic Generation")

        self._v_cycles = tk.IntVar(value=3)
        self._v_delay  = tk.DoubleVar(value=2.0)
        spin(s_traffic, "Cycles / host", self._v_cycles, 1, 100)
        spin(s_traffic, "Delay (sec)",   self._v_delay,  0.5, 60, 0.5)

        # ── LEFT: Domains ───────────────────────────────────────────────────────
        s_domains = section(left, "Domains")
        self._domain_vars = {}
        for d in TOP_20_DOMAINS:
            v = tk.BooleanVar(value=True)
            self._domain_vars[d] = v
            tk.Checkbutton(s_domains, text=d, variable=v,
                           bg=PANEL, fg=FG, selectcolor="#21262d",
                           activebackground=PANEL, activeforeground=ACCENT,
                           font=("Monospace", 8), anchor="w").pack(fill="x", padx=10)

        dbtns = tk.Frame(s_domains, bg=PANEL)
        dbtns.pack(fill="x", padx=10, pady=(2, 8))
        tk.Button(dbtns, text="All",  bg="#21262d", fg=FG, relief="flat", bd=0,
                  width=5, command=lambda: [v.set(True)  for v in self._domain_vars.values()]).pack(side="left")
        tk.Button(dbtns, text="None", bg="#21262d", fg=FG, relief="flat", bd=0,
                  width=5, command=lambda: [v.set(False) for v in self._domain_vars.values()]).pack(side="left", padx=6)

        # ── RIGHT panel ─────────────────────────────────────────────────────────

        # Main action buttons
        act_row = tk.Frame(right, bg=BG)
        act_row.pack(fill="x", pady=(0, 10))

        def act_btn(text, color, cmd, fg_col="#0d1117"):
            b = tk.Button(act_row, text=text, command=cmd,
                          bg=color, fg=fg_col, relief="flat", bd=0,
                          font=("Sans", 10, "bold"), padx=16, pady=8,
                          cursor="hand2", activebackground=color)
            b.pack(side="left", padx=(0, 8))
            return b

        self._btn_traffic = act_btn("▶  Generate Traffic", GREEN,  self._do_traffic)
        self._btn_stop    = act_btn("■  Stop",             "#30363d", self._do_stop, fg_col=DIM)
        self._btn_stop.config(state="disabled")

        tk.Button(act_row, text="⊘  Clear Log",
                  command=self._clear_log,
                  bg=PANEL, fg=DIM, relief="flat", bd=0,
                  font=("Sans", 9), padx=12, pady=8,
                  cursor="hand2").pack(side="right")

        # Progress
        self._progress = ttk.Progressbar(right, mode="indeterminate")
        self._progress.pack(fill="x", pady=(0, 8))

        # Playbook preview
        tk.Label(right, text="LAST PLAYBOOK", font=("Sans", 8, "bold"),
                 bg=BG, fg=DIM, anchor="w").pack(fill="x")
        pb_wrap = tk.Frame(right, bg=PANEL, bd=1, relief="solid",
                           highlightbackground=BORDER)
        pb_wrap.pack(fill="x", pady=(2, 10))
        self._pb_preview = tk.Text(pb_wrap, bg=PANEL, fg="#79c0ff",
                                   font=("Monospace", 8), height=7,
                                   relief="flat", state="disabled", wrap="none")
        sb = ttk.Scrollbar(pb_wrap, orient="horizontal",
                           command=self._pb_preview.xview)
        self._pb_preview.configure(xscrollcommand=sb.set)
        self._pb_preview.pack(fill="x", padx=8, pady=(6, 0))
        sb.pack(fill="x", padx=8, pady=(0, 4))

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

    # ── Mode toggle ────────────────────────────────────────────────────────────

    def _toggle_mode(self):
        if self._v_mode.get() == "dns":
            self._hosts_panel.pack_forget()
            self._dns_panel.pack(fill="x", pady=(0, 8),
                                 before=self._hosts_panel)
        else:
            self._dns_panel.pack_forget()
            self._hosts_panel.pack(fill="x", pady=(0, 8))

    # ── Status checks ──────────────────────────────────────────────────────────

    def _check_ansible(self):
        if ansible_available():
            self._ansible_dot.config(fg="#3fb950")
            self._ansible_lbl.config(text="ansible: ready", fg="#3fb950")
        else:
            self._ansible_dot.config(fg="#f85149")
            self._ansible_lbl.config(text="ansible: NOT FOUND", fg="#f85149")
        self._refresh_dns_pill()

    def _refresh_dns_pill(self):
        active, status = dnsmasq_status()
        color = "#3fb950" if active else "#f85149"
        self._dns_dot.config(fg=color)
        self._dns_lbl.config(text=f"dnsmasq: {status}", fg=color)

    # ── Validation ─────────────────────────────────────────────────────────────

    def _get_domains(self):
        domains = [d for d, v in self._domain_vars.items() if v.get()]
        if not domains:
            messagebox.showerror("Validation", "Select at least one domain.")
        return domains

    def _ansible_kwargs(self):
        return dict(
            inventory        = self._v_inventory.get().strip(),
            limit            = self._v_limit.get().strip() or None,
            ask_pass         = self._v_ask_pass.get(),
            ask_become_pass  = self._v_ask_become.get(),
            vault_password_file = self._v_vault_file.get().strip() or None,
        )

    # ── Playbook preview ───────────────────────────────────────────────────────

    def _show_playbook(self, path):
        try:
            with open(path) as f:
                content = f.read()
        except Exception:
            return
        self._pb_preview.configure(state="normal")
        self._pb_preview.delete("1.0", "end")
        self._pb_preview.insert("end", content)
        self._pb_preview.configure(state="disabled")

    # ── DNS mode actions ───────────────────────────────────────────────────────

    def _do_apply_dns(self):
        domains = self._get_domains()
        if not domains:
            return
        mock_ip = self._v_server_ip.get().strip()
        try:
            write_dnsmasq_conf(mock_ip, domains)
            self._log_msg(f"Wrote dnsmasq config ({len(domains)} domains → {mock_ip})", "ok")
        except PermissionError:
            self._log_msg("Permission denied — run with sudo.", "fail")
            messagebox.showerror("Permission Error",
                                 "Cannot write to /etc/dnsmasq.d/\nRun: sudo python3 traffic_gui_ansible.py")
            return
        self._do_restart_dnsmasq()

    def _do_clear_dns(self):
        try:
            remove_dnsmasq_conf()
            self._log_msg("Removed dnsmasq traffic-sim config.", "warn")
        except Exception as e:
            self._log_msg(f"Failed: {e}", "fail")
            return
        self._do_restart_dnsmasq()

    def _do_restart_dnsmasq(self):
        self._log_msg("Restarting dnsmasq…", "dim")
        ok, out = restart_dnsmasq()
        self._log_msg("dnsmasq restarted." if ok else f"dnsmasq restart failed: {out}",
                      "ok" if ok else "fail")
        self.after(600, self._refresh_dns_pill)

    def _do_push_resolv(self):
        server_ip = self._v_server_ip.get().strip()
        if not server_ip:
            messagebox.showerror("Validation", "Enter this node's IP first.")
            return
        pb = playbook_set_dns(server_ip)
        self._show_playbook(pb)
        self._log_msg(f"Pushing resolv.conf (nameserver {server_ip}) via Ansible…", "info")
        self._run_in_thread(pb)

    def _do_restore_dns(self):
        pb = playbook_restore_dns()
        self._show_playbook(pb)
        self._log_msg("Restoring systemd-resolved on targets via Ansible…", "warn")
        self._run_in_thread(pb)

    # ── Hosts mode actions ─────────────────────────────────────────────────────

    def _do_deploy_hosts(self):
        domains = self._get_domains()
        if not domains:
            return
        mock_ip = self._v_mock_ip.get().strip()
        if not mock_ip:
            messagebox.showerror("Validation", "Enter the mock server IP.")
            return
        pb = playbook_hosts_file(mock_ip, domains)
        self._show_playbook(pb)
        self._log_msg(f"Deploying /etc/hosts entries ({len(domains)} domains → {mock_ip})…", "info")
        self._run_in_thread(pb)

    def _do_remove_hosts(self):
        pb = playbook_remove_hosts()
        self._show_playbook(pb)
        self._log_msg("Removing traffic-sim /etc/hosts entries via Ansible…", "warn")
        self._run_in_thread(pb)

    # ── Ansible ping ───────────────────────────────────────────────────────────

    def _do_ping(self):
        if not ansible_available():
            messagebox.showerror("Ansible", "ansible-playbook not found on PATH.")
            return
        inventory = self._v_inventory.get().strip()
        limit     = self._v_limit.get().strip() or "all"
        self._log_msg(f"Pinging {limit} via {inventory}…", "info")
        self._set_running(True)
        def worker():
            cmd = ["ansible", "-i", inventory, limit, "-m", "ping"]
            if self._v_ask_pass.get():
                cmd.append("--ask-pass")
            if self._v_vault_file.get().strip():
                cmd += ["--vault-password-file", self._v_vault_file.get().strip()]
            try:
                proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                        stderr=subprocess.STDOUT, text=True)
                for line in proc.stdout:
                    line = line.rstrip()
                    if line:
                        tag = "ok" if "SUCCESS" in line else \
                              "fail" if "FAILED" in line or "UNREACHABLE" in line else "default"
                        self._log_msg(f"  {line}", tag)
                proc.wait()
                self._log_msg("Ping complete.", "ok" if proc.returncode == 0 else "fail")
            except Exception as e:
                self._log_msg(f"Ping error: {e}", "fail")
            self.after(0, lambda: self._set_running(False))
        threading.Thread(target=worker, daemon=True).start()

    # ── Traffic generation ─────────────────────────────────────────────────────

    def _do_traffic(self):
        domains = self._get_domains()
        if not domains:
            return
        cycles = self._v_cycles.get()
        delay  = self._v_delay.get()
        pb = playbook_generate_traffic(domains, cycles, delay)
        self._show_playbook(pb)
        self._log_msg(f"Generating traffic: {cycles} cycle(s), {len(domains)} domains, {delay}s delay…", "info")
        self._run_in_thread(pb)

    def _do_stop(self):
        self._stop_flag.set()
        self._log_msg("Stop requested — current playbook will be terminated.", "warn")

    # ── Generic playbook runner ────────────────────────────────────────────────

    def _run_in_thread(self, playbook_path):
        if not ansible_available():
            messagebox.showerror("Ansible", "ansible-playbook not found on PATH.")
            return
        self._stop_flag.clear()
        self._set_running(True)
        kwargs = self._ansible_kwargs()

        def worker():
            rc = run_playbook(
                playbook_path,
                log_fn=self._log_msg,
                stop_flag=self._stop_flag,
                **kwargs
            )
            msg = "Playbook finished successfully." if rc == 0 else f"Playbook exited with code {rc}."
            self._log_msg(msg, "ok" if rc == 0 else "fail")
            self.after(0, lambda: self._set_running(False))

        threading.Thread(target=worker, daemon=True).start()

    # ── Logging ────────────────────────────────────────────────────────────────

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

    # ── State ──────────────────────────────────────────────────────────────────

    def _set_running(self, running):
        self._running = running
        self._btn_traffic.config(state="disabled" if running else "normal")
        self._btn_stop.config(state="normal" if running else "disabled")
        if running:
            self._progress.start(12)
        else:
            self._progress.stop()
            self._progress["value"] = 0


# ── Entry point ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    app = App()
    app.mainloop()
