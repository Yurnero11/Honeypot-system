# 🍯 Honeypot — Multi-Service Deception Network

A lightweight, multi-service honeypot system built in Python that simulates SSH, HTTP, and Redis servers to attract, detect, and log attacker activity. All captured events are mapped to [MITRE ATT&CK](https://attack.mitre.org/) techniques and visualized in a real-time web dashboard.

> ⚠️ **Educational purposes only.** Deploy responsibly and only on infrastructure you own or have permission to monitor.

---

## 📸 Dashboard Preview

The web dashboard provides real-time visibility into attacker activity across all three honeypot services.

- **Timeline** — attack frequency per hour (last 24h)
- **Top IPs** — most active attackers with per-IP log drilldown
- **MITRE ATT&CK** — technique distribution across all events
- **Last Attack** — most recent IOC with full context

---

## 🏗️ Architecture

```
Attacker
   │
   ├── SSH  :2222  →  Fake Linux Shell  (paramiko)   →  ssh.log
   ├── HTTP :8080  →  Fake E-Commerce   (BaseHTTP)   →  http.log
   └── Redis:6379  →  Fake Redis Server (socket)     →  redis.log
                                │
                         log_analyzer.py
                         (pandas parsing)
                                │
                         dashboard.py (Flask)
                                │
                         dashboard.html (Chart.js)
```

### Components

| File | Role |
|---|---|
| `main.py` | Entry point — starts all three honeypots as daemon threads |
| `src/server/ssh/ssh_server.py` | SSH honeypot via `paramiko` |
| `src/server/ssh/fake_commands.py` | Fake Linux filesystem + command interpreter |
| `src/server/http/http_server.py` | HTTP honeypot — fake e-commerce site with SQLi/XSS bait |
| `src/server/redis/redis_server.py` | Redis honeypot — responds to RESP protocol commands |
| `application/log_analyzer.py` | Parses all log files into a unified pandas DataFrame |
| `application/dashboard.py` | Flask API + web dashboard with Basic Auth |
| `application/templates/dashboard.html` | Frontend — Chart.js visualizations |
| `config.yaml` | Central configuration for ports, hosts, and credentials |

---

## 🛡️ Detection Coverage (MITRE ATT&CK)

### SSH Honeypot
| Technique ID | Name | Trigger |
|---|---|---|
| T1110 | Brute Force | `hydra`, `medusa`, failed auth attempts |
| T1059 | Command Execution | `bash -i`, `python3 -c`, `nc -e` |
| T1105 | Ingress Tool Transfer | `wget`, `curl`, `scp` |
| T1068 | Privilege Escalation | `sudo`, `chmod +x`, `./exploit` |
| T1083 | File & Directory Discovery | `cat /etc/shadow`, `ls -l /root` |
| T1018 | Network Scanning | `nmap`, `masscan`, `nc -z` |
| T1049 | Network Discovery | `netstat`, `ifconfig`, `ip addr` |
| T1567 | Exfiltration | `cat /etc/shadow \| curl` |

### HTTP Honeypot
| Technique ID | Name | Trigger |
|---|---|---|
| T1190 | SQL Injection | `' OR 1=1`, `UNION SELECT`, `--` |
| T1552 | Local File Inclusion | `../`, `/etc/passwd`, `/proc/self` |
| T1059 | XSS | `<script>`, `onerror=`, `javascript:` |
| T1078 | Credential Submission | `password=` in POST body |

### Redis Honeypot
| Technique ID | Name | Trigger |
|---|---|---|
| T1078 | Auth Attempt | `AUTH` command |
| T1595 | Active Scanning | `INFO`, `KEYS`, `CONFIG`, `MONITOR` |
| T1496 | Impact | `FLUSHALL`, `SHUTDOWN`, `SAVE` |

---

## ⚙️ Configuration

All settings live in `config.yaml`:

```yaml
server:
  ssh_host: "0.0.0.0"
  ssh_port: 2222
  http_host: "0.0.0.0"
  http_port: 8080
  redis_host: "0.0.0.0"
  redis_port: 6379

credentials:
  ssh:
    username: "admin"
    password: "password"   # bait credentials — intentionally weak

dashboard:
  username: "admin"
  password: "changeme"     # ← CHANGE THIS before deploying

logging:
  level: "INFO"
```

---

## 🚀 Getting Started

### Requirements

- Python 3.10+
- Linux / macOS (Windows not tested)

### Installation

```bash
git clone https://github.com/Yurnero11/Honeypot-system.git
cd honeypot

python -m venv .venv
source .venv/bin/activate

pip install -r requirements.txt
```

### Running the Honeypots

```bash
python main.py
```

All three honeypots start immediately. Logs are written to `logs/raw/`.

### Running the Dashboard

In a separate terminal:

```bash
cd application
python dashboard.py
```

Open [http://127.0.0.1:5000](http://127.0.0.1:5000) and log in with the credentials set in `config.yaml` under `dashboard`.

---

## 📁 Project Structure

```
Honeypot-main/
├── application/
│   ├── templates/
│   │   └── dashboard.html      # Chart.js frontend
│   ├── dashboard.py            # Flask app + Basic Auth
│   └── log_analyzer.py         # Log parser → pandas DataFrame
├── logs/
│   └── raw/
│       ├── ssh.log
│       ├── http.log
│       ├── redis.log
│       └── system.log
├── src/
│   └── server/
│       ├── http/
│       │   └── http_server.py
│       ├── redis/
│       │   └── redis_server.py
│       └── ssh/
│           ├── fake_commands.py
│           └── ssh_server.py
├── config.yaml
├── main.py
├── requirements.txt
└── README.md
```

---

## 📊 Log Format

All services write logs in a unified format:

```
YYYY-MM-DD HH:MM:SS,ms [LEVEL] [LOGGER] MESSAGE
```

**Examples:**

```
2025-01-14 12:34:56,789 [WARNING] [SSH-IOC]   [ATTACK] 192.168.1.10 Detected MITRE: ['T1068_PRIVESC'] via command: sudo su
2025-01-14 12:35:01,123 [WARNING] [HTTP-IOC]  [ATTACK] 192.168.1.10 Path: /login.php - Detected MITRE techniques: ['T1190_SQLI']
2025-01-14 12:35:10,456 [WARNING] [REDIS-IOC] [ATTACK] [192.168.1.10] CMD=FLUSHALL | MITRE=['T1496_IMPACT']
2025-01-14 12:34:50,000 [INFO]    [SSH]       [AUTH SUCCESS] 192.168.1.10 user=admin
```

---

## 🔒 Security Notes

- The dashboard is protected by HTTP Basic Auth — **always change the default password** in `config.yaml` before exposing it to a network.
- Logs may contain real attacker IP addresses — **do not commit `logs/` to version control** (already in `.gitignore`).
- Run the honeypot inside a VM or isolated environment. Do not run on a machine with sensitive data.
- Ports below 1024 require root privileges on Linux. Consider using higher ports (2222, 8080, 6379) or `authbind`.

---

## 📦 Dependencies

```
flask
pandas
paramiko
pyyaml
```

Install via:
```bash
pip install -r requirements.txt
```

---

## 🗺️ Roadmap

- [ ] GeoIP lookup for attacking IPs
- [ ] Telegram / email alerts on new IOC
- [ ] Docker support for isolated deployment
- [ ] Rate limiting on dashboard API
- [ ] Export logs to JSON / CSV from dashboard

---

