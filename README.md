# 🔭 Port Scanner

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.8%2B-blue?style=flat-square&logo=python" />
  <img src="https://img.shields.io/badge/Tool-Port%20Scanning-purple?style=flat-square" />
  <img src="https://img.shields.io/badge/Category-Network%20Recon-red?style=flat-square" />
</p>

> A fast, concurrent TCP port scanner built with Python's `ThreadPoolExecutor`. Supports custom port ranges, configurable threads, and is designed for CTF and authorized pentesting workflows.

---

## 📌 What It Does

`portscanner.py` performs TCP connect scans against a target host:

- ⚡ **Concurrent scanning** — uses threading for high-speed results
- 🎯 **Flexible port input** — comma-separated lists, ranges, or mixed
- 🏁 **Open port summary** — clean summary after each scan
- ⏱️ **Configurable timeout** — tune for speed vs. accuracy

---

## 📦 Installation

No external dependencies. Uses Python standard library only.

```bash
python3 --version  # Requires Python 3.8+
```

---

## 🚀 Usage

```bash
python3 portscanner.py <host> [options]
```

### Arguments

| Argument | Description | Default |
|----------|-------------|---------|
| `host` | Target hostname or IP address | Required |
| `-p, --ports` | Ports to scan. Supports `80,443,8000-8003` format | Common ports |
| `-t, --timeout` | Connection timeout in seconds | `3` |
| `--threads` | Number of concurrent threads | `10` |

### Default Port Set

When no `-p` flag is given, scans these common ports:

```
20-25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 5900, 8080, 8443
```

---

## 💡 Examples

```bash
# Scan default common ports
python3 portscanner.py 192.168.1.1

# Scan specific ports
python3 portscanner.py example.com -p 22,80,443,8080,8443

# Scan a full range
python3 portscanner.py 10.10.10.5 -p 1-1024

# Fast scan with more threads, shorter timeout
python3 portscanner.py 10.10.10.5 -p 1-65535 --threads 100 -t 1

# Mixed range syntax
python3 portscanner.py target.htb -p 21,22,80,443,3000-3010,8080-8090
```

---

## 📋 Sample Output

```
Scanning 14 ports on 192.168.1.100...
--------------------------------------------------
Port    22: OPEN
Port    80: OPEN
Port   110: CLOSED
Port   143: CLOSED
Port   443: OPEN
Port  3306: CLOSED
Port  3389: CLOSED
Port  8080: OPEN
--------------------------------------------------
Scan complete. Open ports: 4
Open ports: 22, 80, 443, 8080
Scan took 3.14 seconds
```

---

## 🧩 Use in CTF / Bug Bounty

| Scenario | Command |
|----------|---------|
| HTB/THM initial recon | `python3 portscanner.py 10.10.10.X -p 1-10000 --threads 50 -t 1` |
| Web-only bug bounty | `python3 portscanner.py target.com -p 80,443,8000-8999` |
| Check for exposed DBs | `python3 portscanner.py target.com -p 3306,5432,27017,6379` |
| Remote access services | `python3 portscanner.py target.com -p 22,23,3389,5900` |

### Pro Tips 🎯

- Combine with `recon.sh` — run port scan first, then feed open ports to nmap for `-sV` service detection
- On CTF machines: scan `1-65535` with `--threads 100 -t 1` for speed
- For bug bounty: stay within scope — don't scan ports on assets not listed in scope

---

## ⚙️ How It Works

```
Target Host
    │
    ▼
ThreadPoolExecutor (N threads)
    │
    ├─ Thread 1: TCP connect → port 80  → OPEN
    ├─ Thread 2: TCP connect → port 22  → OPEN
    ├─ Thread 3: TCP connect → port 443 → OPEN
    └─ Thread N: TCP connect → port ... → CLOSED
    │
    ▼
Aggregate results → Print summary
```

Uses `socket.connect_ex()` — returns `0` for open, non-zero for closed/filtered.

---

## 🔙 Back to Toolkit

[← Return to main README](../README.md)
