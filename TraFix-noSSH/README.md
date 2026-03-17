# Network Traffic Simulator — DNS Mode
## Sandboxed Cybersecurity Training Environment

Simulates realistic HTTP traffic to the top 20 US domains with **zero per-host
configuration after initial setup**. Uses a local dnsmasq DNS server instead of
modifying `/etc/hosts` on every machine.

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│  LAB NETWORK (sandboxed, no internet)                            │
│                                                                  │
│  ┌──────────────────────────────────┐                            │
│  │  SERVER HOST  (runs the GUI)     │                            │
│  │                                  │                            │
│  │  traffic_gui.py  ──writes──►  /etc/dnsmasq.d/traffic-sim.conf│
│  │                  ──restarts──► dnsmasq (port 53)             │
│  │                                                               │
│  │  mock_server.py  (HTTP, port 80)                             │
│  └──────────────────────────────────┘                            │
│           │ DNS queries (port 53)                                │
│           │ HTTP responses (port 80)                             │
│           ▼                                                      │
│  ┌─────────────────┐                                             │
│  │  Target Hosts   │  /etc/resolv.conf → server host IP         │
│  │  (set once)     │  (that's all — no other config needed)     │
│  └─────────────────┘                                             │
└──────────────────────────────────────────────────────────────────┘
```

---

## Prerequisites

### On the server host (where you run the GUI)

```bash
# Install dnsmasq
sudo apt update && sudo apt install dnsmasq -y
sudo systemctl enable dnsmasq

# Install Python dependencies
pip install flask paramiko

# tkinter (usually pre-installed)
sudo apt install python3-tk
```

### On each target host (Ubuntu/Debian) — done once only

**Option 1 — Temporary (lost on reboot):**
```bash
echo "nameserver <SERVER_IP>" | sudo tee /etc/resolv.conf
```

**Option 2 — Permanent (survives reboot):**
```bash
# Disable systemd-resolved which overwrites resolv.conf
sudo systemctl disable --now systemd-resolved
sudo rm -f /etc/resolv.conf
echo "nameserver <SERVER_IP>" | sudo tee /etc/resolv.conf
sudo chattr +i /etc/resolv.conf   # make immutable (optional)
```

---

## Usage

### 1. Start the mock HTTP server (server host)
```bash
sudo python3 mock_server.py --host 0.0.0.0 --port 80
```

### 2. Launch the GUI (server host, needs sudo for dnsmasq config)
```bash
sudo python3 traffic_gui.py
```

### 3. In the GUI:
1. Set **This host's IP** to the server host's LAN IP
2. Check/uncheck the domains you want active
3. Click **⚙ Apply DNS** — writes config and restarts dnsmasq
4. Choose traffic source: **Local** (curl from server) or **Remote** (SSH to targets)
5. Click **▶ Generate Traffic**

---

## GUI Sections

| Section | Purpose |
|---|---|
| **DNS Server** | Set server IP, apply/clear DNS config, restart dnsmasq |
| **Target Host Setup** | Copy-paste instructions for setting resolv.conf on targets |
| **Traffic Generation** | Local or remote (SSH) curl traffic, cycles, delay, threads |
| **Domains** | Enable/disable individual domains |
| **Active DNS Config** | Live preview of the deployed dnsmasq config file |
| **Activity Log** | Timestamped output for all operations |

### Traffic Modes

| Mode | How it works | When to use |
|---|---|---|
| **Local** | Runs curl on the server host itself | Quick testing, verifying DNS works |
| **Remote (SSH)** | SSH into each target, runs curl there | True multi-host traffic simulation |

> Remote SSH mode only runs `curl` — no sudo required on targets.

---

## dnsmasq Config Example

The GUI writes to `/etc/dnsmasq.d/traffic-sim.conf`:

```
# traffic-sim — managed by traffic_gui.py — DO NOT EDIT MANUALLY
address=/google.com/192.168.1.254
address=/www.google.com/192.168.1.254
address=/youtube.com/192.168.1.254
address=/www.youtube.com/192.168.1.254
...
```

**Clear DNS** removes this file and restarts dnsmasq, restoring normal DNS behaviour.

---

## Top 20 Domains Simulated

google.com · youtube.com · facebook.com · amazon.com · wikipedia.org
twitter.com · x.com · reddit.com · instagram.com · linkedin.com
netflix.com · bing.com · microsoft.com · apple.com · espn.com
cnn.com · nytimes.com · twitch.tv · ebay.com · yahoo.com · zoom.us

---

## Troubleshooting

| Problem | Fix |
|---|---|
| `Permission denied` writing config | Run `sudo python3 traffic_gui.py` |
| dnsmasq won't start | Check `sudo journalctl -u dnsmasq -n 30` |
| Targets not resolving | Verify `/etc/resolv.conf` on target has server IP |
| `systemd-resolved` overwriting resolv.conf | Disable it: `sudo systemctl disable --now systemd-resolved` |
| HTTP 000 in traffic log | Check mock_server.py is running on port 80 |
| Port 80 permission denied | Run mock_server.py with `sudo` |
| dnsmasq conflicts with port 53 | `sudo systemctl disable --now systemd-resolved` first |
