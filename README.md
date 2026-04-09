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
