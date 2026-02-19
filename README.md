# Network Traffic Simulator — Sandboxed Lab Environment
## Cybersecurity Training Tool

Simulates realistic HTTP traffic to the top 20 US domains **without internet access**.
Works entirely within your sandboxed network.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  LAB NETWORK (sandboxed, no internet)                       │
│                                                             │
│   ┌─────────────┐      /etc/hosts edits      ┌──────────┐  │
│   │  GUI Host   │ ──── SSH (password) ──────► │ Target  │  │
│   │             │                             │  Hosts  │  │
│   │traffic_gui  │      HTTP traffic           │ (1..N)  │  │
│   │    .py      │ ◄─── curl requests ───────► └──────┬──┘  │
│   └─────────────┘                                    │      │
│                                                      │      │
│   ┌─────────────┐                                    │      │
│   │  Mock Server│ ◄── HTTP on port 80 ───────────────┘      │
│   │ mock_server │    (thinks it's google.com etc.)          │
│   │    .py      │                                           │
│   └─────────────┘                                           │
└─────────────────────────────────────────────────────────────┘
```

**Flow:**
1. GUI pushes `/etc/hosts` entries to each target host via SSH  
   → Points all 20 domains at your mock server IP  
2. Mock server responds to any HTTP request, pretending to be the right domain  
3. GUI triggers `curl` on each host to generate traffic across all domains  

---

## Setup

### 1. Install dependencies (GUI host)
```bash
pip install paramiko flask
# tkinter is usually pre-installed on Linux desktop distributions
# If not: sudo apt install python3-tk
```

### 2. Start the mock server
Run this on a dedicated host (or the GUI host itself):
```bash
# Needs port 80 — run as root or use sudo
sudo python3 mock_server.py --host 0.0.0.0 --port 80
```

> **Tip:** To run without sudo, use port 8080:
> `python3 mock_server.py --port 8080`
> Then update the curl commands in `traffic_gui.py` accordingly.

### 3. Launch the GUI
```bash
python3 traffic_gui.py
```

---

## GUI Reference

| Field | Description |
|---|---|
| **Username** | SSH user on target hosts (needs sudo) |
| **Password** | SSH password (also used for sudo) |
| **IP Range** | Hosts to configure. See formats below. |
| **Mock Server IP** | IP of the host running mock_server.py |
| **Cycles / host** | How many times to loop through all domains |
| **Delay (sec)** | Pause between cycles |
| **Threads** | Parallel SSH connections |

### IP Range Formats
| Format | Example |
|---|---|
| CIDR | `192.168.1.0/24` |
| Dash range | `10.0.0.1-50` |
| Comma list | `10.0.0.1, 10.0.0.5, 10.0.0.9` |

### Buttons
| Button | Action |
|---|---|
| **▶ Deploy & Run** | Push `/etc/hosts` + generate traffic |
| **⚙ Hosts Only** | Only modify `/etc/hosts`, no traffic |
| **✕ Remove Hosts** | Clean up all simulator entries from hosts |
| **■ Stop** | Abort after current host finishes |

---

## /etc/hosts Changes

The tool adds a clearly marked block to each target's `/etc/hosts`:

```
# === TRAFFIC-SIM START ===
192.168.1.254  google.com www.google.com
192.168.1.254  youtube.com www.youtube.com
...
# === TRAFFIC-SIM END ===
```

The **Remove Hosts** button cleanly removes this block, restoring the original file.

---

## Target Host Requirements

- Linux with `curl` installed
- SSH server running (`openssh-server`)
- SSH user must have sudo access (for writing `/etc/hosts`)
- Passwordless sudo is ideal; if sudo requires a password it uses the SSH password

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
| `SSH failed: Authentication failed` | Check username/password |
| `Failed to write /etc/hosts` | Ensure user has sudo rights |
| HTTP 000 in traffic log | Check mock server is running and reachable |
| `tkinter` not found | `sudo apt install python3-tk` |
| Port 80 permission denied | Run mock_server.py with `sudo` |
