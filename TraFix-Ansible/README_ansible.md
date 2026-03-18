# Network Traffic Simulator — Ansible Edition
## Sandboxed Cybersecurity Training Environment

No paramiko. No SSH handling in Python. The GUI writes Ansible playbooks and
calls `ansible-playbook` as a subprocess — your existing inventory, credentials,
and vault config all work transparently.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│  ANSIBLE CONTROL NODE  (where you run the GUI)                      │
│                                                                     │
│  traffic_gui_ansible.py                                             │
│    │                                                                │
│    ├─ writes playbooks to ~/.traffic-sim/playbooks/                 │
│    ├─ calls ansible-playbook as subprocess                          │
│    ├─ streams output live to the GUI log                            │
│    │                                                                │
│    ├── DNS MODE: manages local dnsmasq                              │
│    │     writes /etc/dnsmasq.d/traffic-sim.conf                     │
│    │     restarts dnsmasq locally                                   │
│    │     Ansible pushes resolv.conf to targets                      │
│    │                                                                │
│    └── HOSTS MODE: Ansible pushes /etc/hosts to targets            │
│          uses blockinfile — idempotent, clean removal               │
│                                                                     │
│  mock_server.py  (HTTP, port 80)  — impersonates all 20 domains    │
└─────────────────────────────────────────────────────────────────────┘
         │ Ansible SSH (your existing setup)
         ▼
  Target hosts (Ubuntu/Debian)
```

---

## Prerequisites

### Control node
```bash
# Ansible (if not already installed)
sudo apt install ansible -y

# Python deps (no paramiko needed!)
pip install flask

# tkinter
sudo apt install python3-tk
```

### Target hosts — nothing extra needed
Your existing Ansible connectivity handles everything.

---

## Usage

### 1. Start the mock HTTP server
```bash
sudo python3 mock_server.py --host 0.0.0.0 --port 80
```

### 2. Launch the GUI
```bash
# DNS mode needs sudo (writes to /etc/dnsmasq.d/)
sudo python3 traffic_gui_ansible.py

# Hosts mode only — no sudo needed on control node
python3 traffic_gui_ansible.py
```

---

## GUI Sections

### Ansible Settings
| Field | Description |
|---|---|
| Inventory file | Path to your existing inventory (INI or YAML) |
| Limit | Restrict to a group or IP: `webservers`, `192.168.1.0/24`, `all` |
| Vault pass file | Path to vault password file (leave blank if unused) |
| --ask-pass | Prompt for SSH password at playbook run |
| --ask-become-pass | Prompt for sudo password at playbook run |
| ⚡ Test Connectivity | Runs `ansible -m ping` against your inventory |

### Host Config Mode (toggle between)

**DNS Mode** — recommended
- GUI writes dnsmasq config locally, restarts dnsmasq
- "Push resolv.conf" button deploys `nameserver <this IP>` to all targets via Ansible
- One Ansible run, all hosts configured

**Hosts Mode** — alternative
- Ansible uses `blockinfile` to add entries to `/etc/hosts` on each target
- Clean removal via "Remove Hosts" button
- Requires `become: yes` (sudo) on targets

### Traffic Generation
- Runs an Ansible playbook that executes `curl` in a loop on each target
- Configurable cycles and delay between cycles
- Live output streamed to the activity log

---

## Generated Playbooks

All playbooks are written to `~/.traffic-sim/playbooks/` and previewed in the GUI:

| Playbook | Purpose |
|---|---|
| `deploy_hosts.yml` | Add domain entries to /etc/hosts on targets |
| `remove_hosts.yml` | Remove traffic-sim entries from /etc/hosts |
| `generate_traffic.yml` | Run curl traffic from target hosts |
| `set_dns.yml` | Set resolv.conf on targets (DNS mode) |
| `restore_dns.yml` | Restore systemd-resolved on targets |

You can inspect, edit, or run these playbooks manually with `ansible-playbook`.

---

## Troubleshooting

| Problem | Fix |
|---|---|
| `ansible-playbook not found` | `sudo apt install ansible` or check PATH |
| Permission denied on dnsmasq config | Run with `sudo python3 traffic_gui_ansible.py` |
| Hosts unreachable | Click ⚡ Test Connectivity; check inventory and SSH keys |
| Vault errors | Set vault password file path in GUI |
| systemd-resolved overwriting resolv.conf | Use "Push resolv.conf" button — playbook disables it |
| HTTP 000 in traffic | Check mock_server.py is running and reachable on port 80 |
| Port 80 permission denied | `sudo python3 mock_server.py` |
