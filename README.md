# 🌐 HTTP Analyzer

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.8%2B-blue?style=flat-square&logo=python" />
  <img src="https://img.shields.io/badge/Tool-HTTP%20Analysis-orange?style=flat-square" />
  <img src="https://img.shields.io/badge/Category-Web%20Recon-red?style=flat-square" />
</p>

> Analyze HTTP response headers, detect missing security headers, identify server info disclosure, and export results to JSON — all from the command line.

---

## 📌 What It Does

`http_analyzer.py` sends HTTP/HTTPS requests to a target and inspects the response for:

- ✅ **Security headers** — checks for presence of 7 critical headers
- ⚠️ **Missing security headers** — flags what's absent
- 🕵️ **Server info disclosure** — detects headers leaking tech stack (e.g., `X-Powered-By`, `Server`)
- 🔒 **SSL/TLS behavior** — handles cert errors gracefully with fallback logic
- 📄 **JSON export** — save results for reporting or pipeline use

---

## 🛡️ Security Headers Checked

| Header | Purpose |
|--------|---------|
| `Strict-Transport-Security` | Enforces HTTPS |
| `Content-Security-Policy` | Prevents XSS/injection |
| `X-Content-Type-Options` | Stops MIME sniffing |
| `X-Frame-Options` | Clickjacking protection |
| `X-XSS-Protection` | Legacy XSS filter |
| `Referrer-Policy` | Controls referrer info leakage |
| `Permissions-Policy` | Restricts browser feature access |

---

## 📦 Installation

```bash
pip install requests
```

No other external dependencies required.

---

## 🚀 Usage

```bash
python3 http_analyzer.py <target> [options]
```

### Arguments

| Argument | Description | Default |
|----------|-------------|---------|
| `target` | URL or hostname (e.g. `example.com` or `https://example.com`) | Required |
| `--method` | HTTP method: `GET` or `HEAD` | `GET` |
| `--timeout` | Request timeout in seconds | `10` |
| `--insecure` | Disable SSL certificate verification | `False` |
| `--json FILE` | Export results to JSON file | None |
| `--headers` | Show all raw response headers | `False` |

---

## 💡 Examples

```bash
# Basic scan
python3 http_analyzer.py example.com

# Use HEAD method, export to JSON
python3 http_analyzer.py https://target.com --method HEAD --json results.json

# Skip SSL verification (for self-signed certs)
python3 http_analyzer.py https://internal.target.com --insecure

# Full headers dump
python3 http_analyzer.py https://target.com --headers

# Custom timeout for slow targets
python3 http_analyzer.py https://target.com --timeout 30
```

---

## 📋 Sample Output

```
======================================================================
HTTP Analysis Results
======================================================================

Target: https://example.com
Method: GET
Status Code: 200

--- Security Headers ---
  ✓ Strict-Transport-Security
    max-age=31536000; includeSubDomains
  ✓ X-Content-Type-Options
    nosniff

--- Missing Security Headers ---
  ✗ Content-Security-Policy
  ✗ Referrer-Policy
  ✗ Permissions-Policy

--- Server Information ---
  Server: nginx/1.18.0
  X-Powered-By: PHP/8.0.3

--- Analysis ---
  ✓ Status 200: Success
  ✓ Using HTTPS
  ⚠ Information disclosure: Server
  ⚠ Information disclosure: X-Powered-By
  Cache-Control: no-cache, no-store

======================================================================
```

---

## 🧩 Use in CTF / Bug Bounty

- **Bug bounty**: Missing `CSP` or `HSTS` headers can be low/info findings on some programs
- **XSS chains**: Lack of `Content-Security-Policy` opens door for stored/reflected XSS
- **Info disclosure**: `X-Powered-By: PHP/5.6.0` → hunt for known CVEs on that version
- **CTF recon**: Custom response headers often hide flags or version hints

---

## 📤 JSON Export Format

```json
{
  "url": "https://example.com",
  "method": "GET",
  "timestamp": "2026-04-09T12:00:00",
  "status_code": 200,
  "headers": { ... },
  "security_headers": { "Strict-Transport-Security": "max-age=31536000" },
  "missing_security_headers": ["Content-Security-Policy", "Referrer-Policy"],
  "server_info": { "Server": "nginx/1.18.0" },
  "analysis": ["✓ Using HTTPS", "⚠ Information disclosure: Server"]
}
```

---

## 🔙 Back to Toolkit

[← Return to main README](../README.md)






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





# 🕵️ BugHunter Recon Suite v2.0

<p align="center">
  <img src="https://img.shields.io/badge/Bash-5.0%2B-green?style=flat-square&logo=gnu-bash" />
  <img src="https://img.shields.io/badge/Tool-Recon%20Suite-darkred?style=flat-square" />
  <img src="https://img.shields.io/badge/Category-Bug%20Bounty%20%7C%20CTF-red?style=flat-square" />
  <img src="https://img.shields.io/badge/Tools-20%2B%20Integrated-blue?style=flat-square" />
</p>

> A full-spectrum, modular bash recon automation suite for bug bounty hunters. Integrates 20+ tools across DNS, subdomain enumeration, HTTP probing, directory fuzzing, URL discovery, port scanning, and vulnerability scanning — all in one run.

---

## 📌 What It Does

`recon.sh` automates the entire reconnaissance workflow against a target domain:

1. 🔍 **DNS Enumeration** — nslookup, dig (all record types), dnsrecon, zone transfer attempts
2. 📋 **WHOIS Lookup** — registration info, ASN data
3. 🌐 **HTTP Analysis** — curl header grabs, httpx probing, WhatWeb fingerprinting
4. 🌿 **Subdomain Discovery** — subfinder, amass, assetfinder, ffuf DNS/vhost fuzzing
5. 📜 **URL Collection** — waybackurls, gau (historical URL archives)
6. 🔌 **Port Scanning** — nmap service detection, masscan sweeps
7. 📂 **Directory Fuzzing** — ffuf, gobuster, feroxbuster (recursive)
8. 💣 **Vulnerability Scanning** — nuclei, nikto
9. 🔀 **Deduplication** — anew merges all subdomain and URL lists automatically

---

## 📦 Prerequisites

### Required (minimal run)
```bash
sudo apt install -y dnsutils whois curl
```

### Recommended (full run)
```bash
# Go tools
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/tomnomnom/assetfinder@latest
go install github.com/tomnomnom/anew@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/ffuf/ffuf/v2@latest
go install github.com/OJ/gobuster/v3@latest
go install -v github.com/owasp-amass/amass/v4/...@master

# APT tools
sudo apt install -y nmap masscan whatweb nikto jq
pip install dnsrecon

# Feroxbuster
curl -sL https://raw.githubusercontent.com/epi052/feroxbuster/main/install-nix.sh | bash

# Wordlists
sudo apt install -y seclists
```

> **Note:** The script auto-detects which tools are installed and skips or uses fallbacks for anything missing. A minimal run with just `curl`, `dig`, and `whois` is still useful.

---

## 🚀 Usage

```bash
chmod +x recon.sh
./recon.sh [options] <target_host>
```

### Arguments

| Flag | Description | Default |
|------|-------------|---------|
| `target_host` | Domain or IP to recon | Required |
| `-q, --quick` | Skip heavy scans (nmap, masscan, nuclei, nikto, fuzzing) | `false` |
| `-v, --verbose` | Enable debug output | `false` |
| `-t, --timeout SEC` | Request timeout per tool | `10` |
| `-r, --rate-limit NUM` | Rate limit for supported tools | `1000` |
| `-h, --help` | Show help text | — |

---

## 💡 Examples

```bash
# Full recon on a bug bounty target
./recon.sh tesla.com

# Quick passive-only recon (fast, no fuzzing/scanning)
./recon.sh -q example.com

# Verbose with custom rate limit
./recon.sh -v --rate-limit 200 target.com

# Slow-target adjustment
./recon.sh --timeout 30 --rate-limit 100 slow-target.com
```

---

## 📁 Output Structure

Results are saved to `./recon_results/<target>_<timestamp>/`:

```
recon_results/example.com_20260409_120000/
├── 00_all_subdomains.txt       ← Deduplicated master subdomain list
├── 00_all_urls.txt             ← Deduplicated master URL list
├── 01_nslookup.txt             ← Baseline DNS
├── 02_dig.txt                  ← Full DNS records (A, MX, NS, TXT, SPF, DMARC...)
├── 03_dnsrecon.txt             ← Deep DNS recon
├── 04_whois.txt                ← WHOIS data
├── 05_curl_http.txt            ← HTTP headers
├── 06_curl_https.txt           ← HTTPS headers + redirect chain
├── 07_httpx.txt                ← httpx probing (status, title, tech)
├── 08_whatweb.txt              ← Technology fingerprinting
├── 09_reverse_dns.txt          ← Reverse DNS
├── 10_zone_transfer.txt        ← AXFR attempt
├── 11_subfinder.txt            ← Passive subdomains
├── 12_assetfinder.txt          ← More passive subdomains
├── 13_amass.txt                ← Amass subdomains
├── 13b_ffuf_dns_subdomains.*   ← ffuf DNS-mode subdomain fuzz
├── 13c_ffuf_vhost_subdomains.* ← ffuf vhost-mode subdomain fuzz
├── 14_waybackurls.txt          ← Archived URLs
├── 15_gau.txt                  ← GetAllURLs results
├── 16_nmap.txt                 ← Port/service scan
├── 17_masscan.txt              ← Fast port sweep
├── 20_ffuf_http.*              ← Directory fuzzing (HTTP)
├── 21_ffuf_https.*             ← Directory fuzzing (HTTPS)
├── 22_gobuster_dir.txt         ← Gobuster directory brute-force
├── 23_gobuster_vhost.txt       ← Gobuster vhost enum
├── 24_nuclei.txt               ← Vulnerability scan results
├── 24_nuclei_subdomains.txt    ← Nuclei on all subdomains
├── 25_nikto.txt                ← Nikto web scan
├── 26_feroxbuster_https.txt    ← Recursive content discovery (HTTPS)
├── 27_feroxbuster_http.txt     ← Recursive content discovery (HTTP)
└── ferox_<subdomain>.txt       ← Per-subdomain feroxbuster scans
```

---

## 🗺️ Recon Workflow

```
TARGET DOMAIN
      │
      ▼
┌─────────────────┐
│  DNS & WHOIS    │  nslookup / dig / dnsrecon / whois
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  HTTP Probing   │  curl / httpx / whatweb
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Subdomain Enum │  subfinder / amass / assetfinder / ffuf
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  URL Collection │  waybackurls / gau → 00_all_urls.txt
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Port Scanning  │  nmap / masscan
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Dir Fuzzing    │  ffuf / gobuster / feroxbuster
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Vuln Scanning  │  nuclei / nikto
└─────────────────┘
```

---

## 🧩 Use in CTF / Bug Bounty

| Scenario | Command |
|----------|---------|
| Bug bounty initial recon | `./recon.sh target.com` |
| CTF — quick passive info | `./recon.sh -q ctf-target.com` |
| Check subdomain attack surface | `./recon.sh -q target.com` → see `00_all_subdomains.txt` |
| Historical endpoint mining | `./recon.sh -q target.com` → see `00_all_urls.txt` |
| Tech stack fingerprint only | `./recon.sh -q -v target.com` → `08_whatweb.txt` + `07_httpx.txt` |

### Pro Tips 🎯

- Start with `-q` (quick mode) to get passive intel fast, then re-run without it for full scans
- Feed `00_all_subdomains.txt` into nuclei or httpx for deeper per-subdomain analysis
- Pipe `00_all_urls.txt` through `grep -E "\.(php|asp|aspx|jsp)"` to find juicy endpoints
- DMARC/SPF from `02_dig.txt` can reveal email infrastructure for phishing analysis in scope

---

## 🔙 Back to Toolkit

[← Return to main README](../README.md)

