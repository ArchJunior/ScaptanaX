# ScaptanaX

A fast, multi-threaded network scanner and vulnerability discovery tool for Python — combines port scanning with automatic CVE matching and clean HTML reporting, all from a single script.

```
python scaptanax.py -t example.com -A --cve --headers -o report.html
```

## Why ScaptanaX?

Scanning a target is only the first step — figuring out what those open ports actually mean, checking them against known vulnerabilities, and turning it all into a readable report usually takes several separate tools. ScaptanaX handles that whole pipeline in one command:

- Automatically queries detected services against the **NVD vulnerability database**, showing known CVEs with CVSS scores.
- Analyzes HTTP services for missing security headers (`CSP`, `HSTS`, `X-Frame-Options`, etc.).
- Rolls all findings into a single **risk score** (LOW / MEDIUM / HIGH / CRITICAL).
- Outputs a clean, dark-themed **HTML report** you can open in a browser, or JSON/CSV for automation.

## Features

- TCP Connect and SYN Stealth scanning (requires root for SYN)
- Banner grabbing and service detection
- Aggressive service enumeration (`-sV`) for ports that don't return a banner
- CVE lookup (NVD API v2)
- HTTP security header analysis
- Subnet / CIDR scanning (`192.168.1.0/24`)
- OS fingerprinting (TTL/window/DF based, requires root)
- Risk score calculation
- HTML / JSON / CSV report output
- 6-level timing profile (Paranoid → Insane)

## Installation

**Option 1 — quick install (recommended):**

```bash
git clone https://github.com/ArchJunior/ScaptanaX.git
cd ScaptanaX
bash install.sh
```

This checks your Python version, installs the required dependencies, and installs `scaptanax` as a global command so you can run it from anywhere.

To uninstall:

```bash
bash install.sh --uninstall
```

**Option 2 — manual:**

```bash
git clone https://github.com/ArchJunior/ScaptanaX.git
cd ScaptanaX
pip install colorama tqdm tabulate jinja2 scapy
python scaptanax.py -t <target>
```

> `scapy` is optional — without it, SYN scan and OS fingerprinting automatically fall back to TCP Connect, so the tool still works.

## Usage

```bash
# Basic scan
python scaptanax.py -t 192.168.1.1

# Specific ports + subnet scan
python scaptanax.py -t 192.168.1.0/24 -p 22,80,443

# Full analysis: aggressive mode + CVE lookup + header analysis + HTML report
python scaptanax.py -t example.com -A --cve --headers -o report.html

# Fast timing profile + service enumeration + JSON output
python scaptanax.py -t 10.0.0.1 --timing 4 -sV -o results.json
```

### Options

| Flag | Description |
|---|---|
| `-t, --target` | Target: IP, hostname, or CIDR |
| `-p, --ports` | Port range (`80`, `1-1024`, `22,80,443`) |
| `-sS` | SYN Stealth scan (requires root) |
| `-O` | OS fingerprinting (requires root) |
| `-sV` | Aggressive service enumeration |
| `--cve` | CVE lookup via NVD |
| `--headers` | HTTP security header analysis |
| `--timing [0-5]` | Timing profile (default: 3) |
| `-A, --aggressive` | Combines `-sS -O -sV` |
| `-o, --output` | Output file (`.html`, `.json`, `.csv`) |
| `--threads` | Thread count (default: 100, max 500) |

Set the optional `NVD_API_KEY` environment variable to remove the CVE lookup rate limit ([get an API key](https://nvd.nist.gov/developers/request-an-api-key)).

## Disclaimer

This tool is intended for use only on systems you own or are explicitly authorized to test. Scanning systems without permission is illegal in most jurisdictions. Use responsibly.
