#!/usr/bin/env python3
"""
Scaptanax
Advanced Port Scanner & Security Analysis Tool

Features:
  - TCP Connect & SYN Stealth Scan
  - Banner Grabbing & Service Detection
  - CVE Lookup (NVD API v2)
  - HTTP Security Header Analysis
  - Aggressive Service Enumeration (-sV)
  - Subnet / CIDR Scanning (192.168.1.0/24)
  - HTML / JSON / CSV Report Output
  - OS Fingerprinting
  - Risk Score Calculation

GitHub: https://github.com/ArchJunior
License: All Rights Reserved — Unauthorized use is prohibited.
"""

import socket
import argparse
import datetime
import json
import csv
import re
import os
import ssl
import sys
import time
import ipaddress
import urllib.request
import urllib.parse
import urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock

try:
    from colorama import Fore, Style, init
except ImportError:
    print("[!] colorama not found: pip install colorama")
    sys.exit(1)

try:
    from tqdm import tqdm
except ImportError:
    print("[!] tqdm not found: pip install tqdm")
    sys.exit(1)

try:
    from tabulate import tabulate
except ImportError:
    print("[!] tabulate not found: pip install tabulate")
    sys.exit(1)

try:
    import jinja2
    JINJA2_AVAILABLE = True
except ImportError:
    JINJA2_AVAILABLE = False

try:
    from scapy.all import IP, TCP, sr1, RandShort
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

init(autoreset=True)

BANNER = r"""
                            00
                            11
                           ====
                            //
                            //
                            //
                            //
                            //
                            //
                            //
                            /
   _______________________________________________________
  / ___// ____/   |  / __ \/_  __/   |  / | / /   | | |/ /
  \__ \/ /   / /| | / /_/ / / / / /| | /  |/ / /| | |   /
 ___/ / /___/ ___ |/ ____/ / / / ___ |/ /|  / ___ | /   |
/____/\____/_/  |_/_/     /_/ /_/  |_/_/ |_/_/  |_|/_/|_|
"""

PORT_SERVICES = {
    20: "FTP Data",     21: "FTP",          22: "SSH",          23: "Telnet",
    25: "SMTP",          53: "DNS",           80: "HTTP",         110: "POP3",
    143: "IMAP",         443: "HTTPS",        445: "SMB",         139: "NetBIOS",
    3306: "MySQL",       3389: "RDP",         8080: "HTTP-Alt",   8443: "HTTPS-Alt",
    5432: "PostgreSQL",  6379: "Redis",       27017: "MongoDB",   5900: "VNC",
    11211: "Memcached",  9200: "Elasticsearch", 1521: "Oracle",   1433: "MSSQL",
    2049: "NFS",         2181: "ZooKeeper",   4848: "GlassFish",  8888: "Jupyter",
}

PORT_RISK_WEIGHTS = {
    22: 5,     3389: 20,   3306: 25,  445: 15,   139: 15,
    80: 10,    443: 10,    21: 15,    23: 20,    25: 15,
    5432: 20,  6379: 25,   27017: 25, 5900: 20,  11211: 20,
    9200: 25,  1521: 25,   1433: 25,  8888: 20,  2049: 15,
}

SERVICE_REGEX = {
    "Apache":        r"Server: Apache/([\d.]+)",
    "nginx":         r"Server: nginx/([\d.]+)",
    "OpenSSH":       r"SSH-2\.0-OpenSSH_([\d.p]+)",
    "Microsoft IIS": r"Server: Microsoft-IIS/([\d.]+)",
    "MySQL":         r"mysql.{0,30}([\d]+\.[\d]+\.[\d]+)",
    "Redis":         r"redis_version:([\d.]+)",
    "PostgreSQL":    r"PostgreSQL ([\d.]+)",
    "MongoDB":       r"MongoDB ([\d.]+)",
    "vsftpd":        r"vsftpd ([\d.]+)",
    "ProFTPD":       r"ProFTPD ([\d.]+)",
    "lighttpd":      r"Server: lighttpd/([\d.]+)",
    "Tomcat":        r"Apache-Coyote/([\d.]+)|Tomcat/([\d.]+)",
}

CVE_SEARCH_MAP = {
    "Apache":        "apache http server",
    "nginx":         "nginx",
    "OpenSSH":       "openssh",
    "Microsoft IIS": "microsoft iis",
    "MySQL":         "mysql",
    "Redis":         "redis",
    "PostgreSQL":    "postgresql",
    "MongoDB":       "mongodb",
    "vsftpd":        "vsftpd",
    "ProFTPD":       "proftpd",
    "lighttpd":      "lighttpd",
    "Tomcat":        "apache tomcat",
}

SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "desc": "HSTS — enforces HTTPS",
        "risk": "MEDIUM",
    },
    "X-Frame-Options": {
        "desc": "Clickjacking protection",
        "risk": "MEDIUM",
    },
    "X-Content-Type-Options": {
        "desc": "MIME sniffing protection",
        "risk": "LOW",
    },
    "Content-Security-Policy": {
        "desc": "XSS / injection protection",
        "risk": "HIGH",
    },
    "Referrer-Policy": {
        "desc": "Referrer information hiding",
        "risk": "LOW",
    },
    "Permissions-Policy": {
        "desc": "Browser API restriction",
        "risk": "LOW",
    },
    "X-XSS-Protection": {
        "desc": "Legacy browser XSS filter",
        "risk": "LOW",
    },
    "Server": {
        "desc": "Server version disclosure (should be removed)",
        "risk": "INFO",
        "present_is_bad": True,
    },
    "X-Powered-By": {
        "desc": "Backend technology disclosure (should be removed)",
        "risk": "INFO",
        "present_is_bad": True,
    },
}

MAX_THREADS      = 500
VALID_PORT_RANGE = (1, 65535)
NVD_API_BASE     = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_RATE_LIMIT   = 0.7

def parse_banner_for_version(banner: str) -> str:
    """Extracts the service name and version information from a banner."""
    for service, regex in SERVICE_REGEX.items():
        match = re.search(regex, banner, re.IGNORECASE)
        if match:
            version = next((g for g in match.groups() if g), "?")
            return f"{service} {version}"
    cleaned = banner.strip()[:100]
    return cleaned if cleaned else "Unknown"


def extract_service_name(banner: str) -> tuple:
    """
    Returns a (service_name, version) pair from a banner.
    Used for CVE lookups.

    Supports both raw banner ("SSH-2.0-OpenSSH_8.9") and
    parsed banner ("OpenSSH 8.9") formats.
    """
    for service, regex in SERVICE_REGEX.items():
        match = re.search(regex, banner, re.IGNORECASE)
        if match:
            version = next((g for g in match.groups() if g), "")
            return service, version
    parsed_pattern = r"^([A-Za-z][A-Za-z0-9\s]+?)\s+([\d][\d.p\-]+)$"
    match = re.match(parsed_pattern, banner.strip())
    if match:
        svc_candidate = match.group(1).strip()
        version       = match.group(2).strip()
        for service in SERVICE_REGEX:
            if service.lower() in svc_candidate.lower() or svc_candidate.lower() in service.lower():
                return service, version
        return svc_candidate, version
    return "", ""


def parse_ports(port_str: str) -> list:
    """
    Parses and validates a port string.
    Examples: "80", "1-1024", "22,80,443", "1-100,8080,9000-9100"
    """
    if not port_str or port_str.strip() == "1-1024":
        return list(range(1, 1025))

    ports = set()
    try:
        for part in port_str.split(','):
            part = part.strip()
            if not part:
                continue
            if '-' in part:
                bounds = part.split('-')
                if len(bounds) != 2:
                    raise ValueError(f"Invalid range format: '{part}'")
                start, end = int(bounds[0]), int(bounds[1])
                if start > end:
                    raise ValueError(f"Start port cannot be greater than end port: {start}-{end}")
                if not (VALID_PORT_RANGE[0] <= start <= VALID_PORT_RANGE[1]):
                    raise ValueError(f"Invalid port value: {start}")
                if not (VALID_PORT_RANGE[0] <= end <= VALID_PORT_RANGE[1]):
                    raise ValueError(f"Invalid port value: {end}")
                ports.update(range(start, end + 1))
            else:
                p = int(part)
                if not (VALID_PORT_RANGE[0] <= p <= VALID_PORT_RANGE[1]):
                    raise ValueError(
                        f"Port must be in range {VALID_PORT_RANGE[0]}-{VALID_PORT_RANGE[1]}: {p}"
                    )
                ports.add(p)
    except ValueError as e:
        print(Fore.RED + f"[!] Port parse error: {e}")
        sys.exit(1)

    return sorted(ports)


def parse_targets(target_str: str) -> list:
    """
    Parses a single IP, hostname, or CIDR range.
    Examples:
      "192.168.1.1"       → ["192.168.1.1"]
      "192.168.1.0/24"    → ["192.168.1.1", ..., "192.168.1.254"]
      "example.com"       → ["example.com"]
    """
    target_str = target_str.strip()

    if '/' in target_str:
        try:
            network = ipaddress.ip_network(target_str, strict=False)
            hosts = list(network.hosts())
            if not hosts:
                hosts = [network.network_address]
            return [str(h) for h in hosts]
        except ValueError as e:
            print(Fore.RED + f"[!] Invalid CIDR range: {target_str} — {e}")
            sys.exit(1)

    return [target_str]


def get_timing_params(timing: int) -> dict:
    """Returns timeout and delay values based on the timing profile."""
    profiles = {
        0: {"timeout": 5.0,  "delay": 3.0,  "retries": 1},
        1: {"timeout": 3.0,  "delay": 1.0,  "retries": 1},
        2: {"timeout": 2.0,  "delay": 0.5,  "retries": 2},
        3: {"timeout": 1.2,  "delay": 0.1,  "retries": 2},
        4: {"timeout": 0.7,  "delay": 0.0,  "retries": 3},
        5: {"timeout": 0.4,  "delay": 0.0,  "retries": 4},
    }
    return profiles.get(timing, profiles[3])

def query_nvd_cve(service_name: str, version: str, max_results: int = 5) -> list:
    """
    Queries the NVD (National Vulnerability Database) API v2.
    Returns a list of CVEs based on service name and version.

    Returns: [{"id": "CVE-...", "score": 9.8, "severity": "CRITICAL", "desc": "..."}, ...]

    Note: Without an API key, the rate limit is 5 requests/30 seconds.
          Use the NVD_API_KEY environment variable to add an API key.
    """
    search_term = CVE_SEARCH_MAP.get(service_name, service_name.lower())
    if not search_term:
        return []

    params = {
        "keywordSearch": f"{search_term} {version}".strip(),
        "resultsPerPage": max_results,
        "startIndex": 0,
    }

    url = f"{NVD_API_BASE}?{urllib.parse.urlencode(params)}"
    headers = {"User-Agent": "Scaptanax (Security Scanner)"}

    api_key = os.environ.get("NVD_API_KEY", "")
    if api_key:
        headers["apiKey"] = api_key

    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode())

        cves = []
        for item in data.get("vulnerabilities", []):
            cve_obj = item.get("cve", {})
            cve_id  = cve_obj.get("id", "N/A")

            score    = 0.0
            severity = "UNKNOWN"
            metrics  = cve_obj.get("metrics", {})

            if "cvssMetricV31" in metrics:
                cvss = metrics["cvssMetricV31"][0]["cvssData"]
                score    = cvss.get("baseScore", 0.0)
                severity = cvss.get("baseSeverity", "UNKNOWN")
            elif "cvssMetricV30" in metrics:
                cvss = metrics["cvssMetricV30"][0]["cvssData"]
                score    = cvss.get("baseScore", 0.0)
                severity = cvss.get("baseSeverity", "UNKNOWN")
            elif "cvssMetricV2" in metrics:
                cvss = metrics["cvssMetricV2"][0]["cvssData"]
                score    = cvss.get("baseScore", 0.0)
                severity = "HIGH" if score >= 7 else ("MEDIUM" if score >= 4 else "LOW")

            desc = "No description"
            for d in cve_obj.get("descriptions", []):
                if d.get("lang") == "en":
                    desc = d.get("value", "")[:200]
                    break

            cves.append({
                "id":       cve_id,
                "score":    score,
                "severity": severity,
                "desc":     desc,
            })

        cves.sort(key=lambda x: x["score"], reverse=True)
        return cves

    except urllib.error.HTTPError as e:
        if e.code == 429:
            return [{"id": "RATE_LIMITED", "score": 0, "severity": "INFO",
                     "desc": "NVD API rate limit exceeded. Please wait a moment."}]
        return []
    except (urllib.error.URLError, json.JSONDecodeError, KeyError, TimeoutError):
        return []


def run_cve_scan(open_ports: list, delay: float = NVD_RATE_LIMIT) -> dict:
    """
    Scans banners of all open ports and queries for CVEs.
    Returns a port → [cve_list] mapping.
    """
    results = {}
    queried = set()

    print(Fore.CYAN + "\n[*] Starting CVE scan (NVD API)...")

    for entry in open_ports:
        port, service, banner = entry[0], entry[1], entry[2]

        svc_name, version = extract_service_name(banner)
        if not svc_name or svc_name in queried:
            continue

        queried.add(svc_name)
        print(Fore.CYAN + f"    → Querying {svc_name} {version}...")

        cves = query_nvd_cve(svc_name, version)
        if cves:
            results[port] = {"service": svc_name, "version": version, "cves": cves}
            top = cves[0]
            color = Fore.RED if top["score"] >= 7 else Fore.YELLOW
            print(color + f"    ⚠  {top['id']}  CVSS: {top['score']}  [{top['severity']}]")
        else:
            print(Fore.GREEN + f"    ✓  {svc_name} {version} — No known CVEs found")

        time.sleep(delay)

    return results


def cve_severity_color(severity: str) -> str:
    return {
        "CRITICAL": Fore.RED,
        "HIGH":     Fore.LIGHTRED_EX,
        "MEDIUM":   Fore.YELLOW,
        "LOW":      Fore.GREEN,
    }.get(severity.upper(), Fore.WHITE)

def analyze_http_headers(target_ip: str, port: int, timeout: float = 4.0) -> dict:
    """
    Sends a HEAD request to HTTP/HTTPS ports and analyzes security headers.

    Returns:
    {
        "missing":  [{"header": "X-Frame-Options", "desc": "...", "risk": "MEDIUM"}, ...],
        "present":  [{"header": "Server", "value": "Apache/2.4", ...}],
        "raw":      {"Server": "Apache/2.4", ...},
        "score":    0-100,
    }
    """
    use_ssl = port in (443, 8443)
    result  = {"missing": [], "present": [], "raw": {}, "score": 100}

    raw_sock = None
    try:
        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw_sock.settimeout(timeout)
        raw_sock.connect((target_ip, port))

        if use_ssl:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            try:
                conn = ctx.wrap_socket(raw_sock, server_hostname=target_ip)
                raw_sock = None
            except ssl.SSLError:
                return result
        else:
            conn = raw_sock
            raw_sock = None

        request = (
            f"HEAD / HTTP/1.1\r\n"
            f"Host: {target_ip}\r\n"
            f"User-Agent: Scaptanax/3.0\r\n"
            f"Connection: close\r\n\r\n"
        )
        conn.sendall(request.encode())

        response = b""
        while True:
            chunk = conn.recv(4096)
            if not chunk:
                break
            response += chunk
            if b"\r\n\r\n" in response:
                break
        conn.close()

    except (socket.timeout, ConnectionRefusedError, OSError):
        return result
    except Exception:
        return result
    finally:
        if raw_sock:
            try:
                raw_sock.close()
            except Exception:
                pass

    try:
        header_section = response.decode(errors='ignore').split("\r\n\r\n")[0]
        raw_headers = {}
        for line in header_section.split("\r\n")[1:]:  # First line is HTTP/1.1 200 OK
            if ":" in line:
                key, _, val = line.partition(":")
                raw_headers[key.strip()] = val.strip()
        result["raw"] = raw_headers
    except Exception:
        return result

    penalty = 0
    risk_penalty = {"HIGH": 25, "MEDIUM": 15, "LOW": 5, "INFO": 0}

    for header, meta in SECURITY_HEADERS.items():
        present_is_bad = meta.get("present_is_bad", False)
        header_value   = raw_headers.get(header, "")

        if present_is_bad:
            if header_value:
                result["present"].append({
                    "header": header,
                    "value":  header_value,
                    "desc":   meta["desc"],
                    "risk":   meta["risk"],
                    "bad":    True,
                })
                penalty += risk_penalty.get(meta["risk"], 0)
        else:
            if not header_value:
                result["missing"].append({
                    "header": header,
                    "desc":   meta["desc"],
                    "risk":   meta["risk"],
                })
                penalty += risk_penalty.get(meta["risk"], 0)
            else:
                result["present"].append({
                    "header": header,
                    "value":  header_value,
                    "desc":   meta["desc"],
                    "risk":   meta["risk"],
                    "bad":    False,
                })

    result["score"] = max(0, 100 - penalty)
    return result


def run_http_header_scan(target_ip: str, open_ports: list, timeout: float = 4.0) -> dict:
    """
    Runs header analysis for all HTTP/HTTPS ports.
    Returns a port → analysis_result mapping.
    """
    http_ports = [e[0] for e in open_ports if e[0] in (80, 443, 8080, 8443)]
    if not http_ports:
        return {}

    results = {}
    print(Fore.CYAN + "\n[*] Starting HTTP header analysis...")

    for port in http_ports:
        analysis = analyze_http_headers(target_ip, port, timeout)
        results[port] = analysis

        score = analysis["score"]
        color = Fore.GREEN if score >= 80 else (Fore.YELLOW if score >= 50 else Fore.RED)
        print(color + f"    Port {port} — Security score: {score}/100")

        for m in analysis["missing"]:
            risk_col = {"HIGH": Fore.RED, "MEDIUM": Fore.YELLOW, "LOW": Fore.CYAN}.get(
                m["risk"], Fore.WHITE
            )
            print(risk_col + f"      ✗ Missing: {m['header']} ({m['desc']}) [{m['risk']}]")

        for p in analysis["present"]:
            if p.get("bad"):
                print(Fore.YELLOW + f"      ⚠ Disclosure: {p['header']}: {p['value'][:60]}")

    return results

def banner_grab(target_ip: str, port: int, timeout: float = 2.0) -> str:
    """
    Sends port-specific probes to retrieve banner/version information.
    Establishes SSL/TLS connections for ports 443/8443.
    """
    raw_sock = None
    try:
        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw_sock.settimeout(timeout)
        raw_sock.connect((target_ip, port))

        if port in (443, 8443):
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            try:
                ssl_sock = ctx.wrap_socket(raw_sock, server_hostname=target_ip)
                ssl_sock.sendall(
                    b"HEAD / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
                )
                banner   = ssl_sock.recv(2048).decode(errors='ignore').strip()
                ssl_sock.close()
                raw_sock = None
                return parse_banner_for_version(banner)
            except ssl.SSLError:
                return "SSL Handshake Failed"

        probes = {
            21:   b"FEAT\r\n",
            22:   b"SSH-2.0-Scaptanax\r\n",
            25:   b"EHLO scaptanax.local\r\n",
            80:   b"HEAD / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
            110:  b"CAPA\r\n",
            143:  b"A001 CAPABILITY\r\n",
            3306: b"\x00\x00\x00\x00\x01",
            5432: b"\x00\x00\x00\x08\x04\xd2\x16\x2f",
            6379: b"PING\r\n",
            8080: b"HEAD / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        }

        probe = probes.get(port, b"HEAD / HTTP/1.0\r\n\r\n")
        raw_sock.sendall(probe)

        banner   = raw_sock.recv(2048).decode(errors='ignore').strip()
        raw_sock.close()
        raw_sock = None
        return parse_banner_for_version(banner)

    except (socket.timeout, ConnectionRefusedError):
        return "No Banner"
    except OSError as e:
        return f"Socket Error: {e}"
    except Exception as e:
        return f"Banner Error: {type(e).__name__}"
    finally:
        if raw_sock:
            try:
                raw_sock.close()
            except Exception:
                pass

ENUM_PROBES = [
    b"GET / HTTP/1.0\r\n\r\n",
    b"HEAD / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    b"OPTIONS / HTTP/1.0\r\n\r\n",
    b"\r\n",
    b"HELP\r\n",
    b"VERSION\r\n",
    b"",
]

RESPONSE_PATTERNS = [
    (r"HTTP/[\d.]+",                    "HTTP Service"),
    (r"220.*ftp",                       "FTP"),
    (r"220.*smtp|ESMTP",                "SMTP"),
    (r"\+OK",                           "POP3"),
    (r"\* OK.*IMAP",                    "IMAP"),
    (r"SSH-[\d.]+",                     "SSH"),
    (r"RFB \d+\.\d+",                   "VNC"),
    (r"^\x16\x03",                      "TLS/SSL"),
    (r"redis_version",                  "Redis"),
    (r"mysql|MariaDB",                  "MySQL"),
    (r"\x00\x00\x00.*\x0a",            "MySQL (greeting)"),
    (r"PostgreSQL",                     "PostgreSQL"),
    (r"Mongo",                          "MongoDB"),
]


def aggressive_service_enum(target_ip: str, port: int, timeout: float = 2.0) -> str:
    """
    Attempts to detect services on ports that don't respond to banner grabbing
    by sending various probes in sequence.
    Uses a known banner if one is returned, otherwise returns the probe result.
    """
    for probe in ENUM_PROBES:
        raw_sock = None
        try:
            raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            raw_sock.settimeout(timeout)
            raw_sock.connect((target_ip, port))

            if probe:
                raw_sock.sendall(probe)

            response = raw_sock.recv(1024).decode(errors='ignore')
            raw_sock.close()
            raw_sock = None

            if not response.strip():
                continue

            for pattern, svc_name in RESPONSE_PATTERNS:
                if re.search(pattern, response, re.IGNORECASE | re.DOTALL):
                    return f"{svc_name} (enum)"

            parsed = parse_banner_for_version(response)
            if parsed != "Unknown":
                return parsed

            snippet = response.strip().replace("\r", "").replace("\n", " ")[:60]
            return f"Unknown ({snippet})"

        except (socket.timeout, ConnectionRefusedError, OSError):
            continue
        except Exception:
            continue
        finally:
            if raw_sock:
                try:
                    raw_sock.close()
                except Exception:
                    pass

    return "No Response (filtered?)"

def tcp_connect_scan(target_ip: str, port: int, timeout: float = 1.0,
                     aggressive: bool = False):
    """
    Standard TCP Connect scan.
    If aggressive=True, applies service enumeration to ports that don't return banners.
    Returns: (port, service, banner) or None
    """
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((target_ip, port))
        sock.close()
        sock = None

        if result == 0:
            service = PORT_SERVICES.get(port, "Unknown")
            banner  = banner_grab(target_ip, port, timeout)

            # If no banner was received and in aggressive mode, try aggressive enumeration
            if aggressive and banner in ("No Banner", "Unknown"):
                banner = aggressive_service_enum(target_ip, port, timeout)

            return port, service, banner
        return None

    except (socket.timeout, ConnectionRefusedError, OSError):
        return None
    except Exception:
        return None
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass


def syn_scan(target_ip: str, port: int, timeout: float = 1.5,
             aggressive: bool = False):
    """
    SYN Stealth Scan.
    Requires root/sudo privileges.
    Returns: (port, service, banner) or None
    """
    if not SCAPY_AVAILABLE:
        return tcp_connect_scan(target_ip, port, timeout, aggressive)

    try:
        src_port = int(RandShort())
        syn_pkt  = IP(dst=target_ip) / TCP(
            sport=src_port, dport=port, flags="S", seq=1000
        )
        resp = sr1(syn_pkt, timeout=timeout, verbose=0)

        if resp is None:
            return None

        if resp.haslayer(TCP) and resp[TCP].flags == 0x12:  # SYN-ACK
            rst_pkt = IP(dst=target_ip) / TCP(
                sport=src_port, dport=port, flags="R", seq=resp[TCP].ack
            )
            sr1(rst_pkt, timeout=1, verbose=0)

            service = PORT_SERVICES.get(port, "Unknown")
            banner  = banner_grab(target_ip, port, timeout)

            if aggressive and banner in ("No Banner", "Unknown"):
                banner = aggressive_service_enum(target_ip, port, timeout)

            return port, service, banner

        return None

    except PermissionError:
        print(Fore.YELLOW + "\n[!] Root privileges required for SYN scan — falling back to TCP Connect.")
        return tcp_connect_scan(target_ip, port, timeout, aggressive)
    except Exception:
        return None

def os_fingerprint(target_ip: str) -> str:
    if not SCAPY_AVAILABLE:
        return "scapy not available — OS fingerprint skipped"

    try:
        pkt = IP(dst=target_ip) / TCP(
            dport=80, flags="S", window=65535,
            options=[('MSS', 1460), ('WScale', 10), ('SAckOK', b'')]
        )
        resp = sr1(pkt, timeout=3, verbose=0)

        if resp is None or not resp.haslayer(TCP):
            return "No response (filtered/dropped?)"

        ttl    = resp.ttl
        window = resp[TCP].window
        df     = bool(resp[IP].flags & 2)

        if ttl <= 64:
            os_type = "Linux/Unix"
            if window in (5840, 5720, 29200, 65535):
                os_type += " — Modern Linux Kernel"
            elif window == 14600:
                os_type += " — Older Linux"
        elif ttl <= 128:
            os_type = "Windows"
            if window >= 65535:
                os_type += " — Win10/11 or Server 2016+"
            elif window == 8192:
                os_type += " — WinXP/Server 2003"
        elif ttl <= 255:
            os_type = "BSD / Network Device (Cisco/Juniper)"
        else:
            os_type = "Unknown"

        return f"{os_type} | TTL: {ttl} | Win: {window} | DF: {df}"

    except PermissionError:
        return "OS Fingerprint: Root privileges required"
    except Exception as e:
        return f"OS Fingerprint failed: {type(e).__name__}: {e}"

def calculate_risk_level(
    open_ports:   list,
    cve_results:  dict = None,
    os_info:      str  = "",
    http_results: dict = None,
) -> tuple:
    """
    Calculates the risk score.
    Returns: (level_str, raw_score)
    """
    cve_results  = cve_results  or {}
    http_results = http_results or {}
    score = 0

    score += sum(PORT_RISK_WEIGHTS.get(e[0], 5) for e in open_ports)

    for port_data in cve_results.values():
        for cve in port_data.get("cves", []):
            s = cve.get("score", 0)
            if s >= 9.0:
                score += 40
            elif s >= 7.0:
                score += 25
            elif s >= 4.0:
                score += 10
            else:
                score += 5

    for analysis in http_results.values():
        http_score = analysis.get("score", 100)
        score += max(0, (100 - http_score) // 4)

    if "Windows" in os_info:
        score += 25
    elif "Linux" in os_info:
        score += 12
    elif "BSD" in os_info:
        score += 8

    if score > 120:
        level = "CRITICAL"
    elif score > 70:
        level = "HIGH"
    elif score > 40:
        level = "MEDIUM"
    else:
        level = "LOW"

    return level, score


def risk_color(level: str) -> str:
    return {
        "CRITICAL": Fore.RED,
        "HIGH":     Fore.LIGHTRED_EX,
        "MEDIUM":   Fore.YELLOW,
        "LOW":      Fore.GREEN,
    }.get(level, Fore.WHITE)

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Scaptanax Report — {{ meta.target }}</title>
<style>
  :root {
    --bg:       #0d1117;
    --bg2:      #161b22;
    --bg3:      #21262d;
    --border:   #30363d;
    --text:     #e6edf3;
    --text-dim: #8b949e;
    --cyan:     #58a6ff;
    --green:    #3fb950;
    --yellow:   #d29922;
    --red:      #f85149;
    --critical: #ff6e6e;
    --purple:   #bc8cff;
  }
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    background: var(--bg);
    color: var(--text);
    font-family: 'Segoe UI', system-ui, sans-serif;
    font-size: 14px;
    line-height: 1.6;
    padding: 0 0 60px 0;
  }
  /* Header */
  .header {
    background: linear-gradient(135deg, #0d1117 0%, #161b22 100%);
    border-bottom: 1px solid var(--border);
    padding: 36px 48px 28px;
    display: flex;
    align-items: center;
    gap: 24px;
  }
  .logo pre {
    font-size: 10px;
    line-height: 1.2;
    color: var(--cyan);
    white-space: pre;
    font-family: monospace;
  }
  .header-info { flex: 1; }
  .header-info h1 { font-size: 22px; color: var(--cyan); margin-bottom: 6px; }
  .header-info p  { color: var(--text-dim); font-size: 13px; }
  /* Risk badge */
  .risk-badge {
    padding: 10px 22px;
    border-radius: 8px;
    font-weight: 700;
    font-size: 16px;
    letter-spacing: 1px;
    border: 2px solid;
  }
  .risk-CRITICAL { background: rgba(248,81,73,.15);  border-color: var(--red);      color: var(--red);      }
  .risk-HIGH     { background: rgba(248,81,73,.08);  border-color: var(--yellow);   color: var(--yellow);   }
  .risk-MEDIUM   { background: rgba(210,153,34,.1);  border-color: var(--yellow);   color: var(--yellow);   }
  .risk-LOW      { background: rgba(63,185,80,.1);   border-color: var(--green);    color: var(--green);    }
  /* Main layout */
  .container { max-width: 1100px; margin: 32px auto; padding: 0 24px; }
  /* Summary cards */
  .summary-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
    gap: 16px;
    margin-bottom: 32px;
  }
  .card {
    background: var(--bg2);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 18px 20px;
  }
  .card .label { color: var(--text-dim); font-size: 12px; text-transform: uppercase; letter-spacing: .5px; }
  .card .value { font-size: 26px; font-weight: 700; margin-top: 4px; }
  .card .value.cyan   { color: var(--cyan);   }
  .card .value.green  { color: var(--green);  }
  .card .value.yellow { color: var(--yellow); }
  .card .value.red    { color: var(--red);    }
  /* Section titles */
  h2 {
    font-size: 16px;
    color: var(--text-dim);
    border-bottom: 1px solid var(--border);
    padding-bottom: 8px;
    margin: 32px 0 16px;
    text-transform: uppercase;
    letter-spacing: .8px;
  }
  /* Tables */
  table { width: 100%; border-collapse: collapse; }
  th {
    background: var(--bg3);
    color: var(--text-dim);
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: .5px;
    padding: 10px 14px;
    text-align: left;
    border-bottom: 1px solid var(--border);
  }
  td {
    padding: 10px 14px;
    border-bottom: 1px solid var(--border);
    vertical-align: top;
  }
  tr:hover td { background: rgba(88,166,255,.04); }
  .port-num  { color: var(--cyan);   font-family: monospace; font-weight: 600; }
  .service   { color: var(--purple); }
  .banner    { color: var(--text-dim); font-family: monospace; font-size: 12px; }
  /* CVE badges */
  .cve-id    { font-family: monospace; font-weight: 600; font-size: 12px; }
  .severity-CRITICAL { color: var(--critical); }
  .severity-HIGH     { color: var(--red);      }
  .severity-MEDIUM   { color: var(--yellow);   }
  .severity-LOW      { color: var(--green);    }
  .severity-UNKNOWN  { color: var(--text-dim); }
  .score-bar-wrap { background: var(--bg3); border-radius: 4px; height: 6px; width: 80px; margin-top: 4px; }
  .score-bar {
    height: 6px;
    border-radius: 4px;
    background: linear-gradient(90deg, var(--green), var(--yellow), var(--red));
  }
  /* HTTP headers */
  .missing-header { color: var(--red);    font-size: 12px; }
  .present-header { color: var(--green);  font-size: 12px; }
  .bad-header     { color: var(--yellow); font-size: 12px; }
  .http-score-ring {
    display: inline-block;
    width: 36px;
    height: 36px;
    border-radius: 50%;
    border: 3px solid;
    text-align: center;
    line-height: 30px;
    font-weight: 700;
    font-size: 11px;
  }
  /* OS info */
  .os-info { background: var(--bg2); border: 1px solid var(--border); border-radius: 8px; padding: 14px 18px; font-family: monospace; font-size: 13px; color: var(--cyan); }
  /* Footer */
  .footer { text-align: center; color: var(--text-dim); font-size: 12px; margin-top: 48px; border-top: 1px solid var(--border); padding-top: 20px; }
  /* No data */
  .empty { color: var(--text-dim); font-style: italic; padding: 16px 0; }
</style>
</head>
<body>

<div class="header">
  <div class="logo"><pre>SCAPTANAX</pre></div>
  <div class="header-info">
    <h1>{{ meta.target }}</h1>
    <p>Scan time: {{ meta.timestamp }} &nbsp;|&nbsp; Tool: {{ meta.tool }}</p>
    <p>OS Estimate: {{ meta.os_estimate }}</p>
  </div>
  <div class="risk-badge risk-{{ meta.risk_level }}">
    {{ meta.risk_level }}<br>
    <small style="font-size:11px;font-weight:400;">score: {{ meta.risk_score }}</small>
  </div>
</div>

<div class="container">

  <!-- Summary cards -->
  <div class="summary-grid">
    <div class="card">
      <div class="label">Open Ports</div>
      <div class="value cyan">{{ open_ports | length }}</div>
    </div>
    <div class="card">
      <div class="label">CVEs Found</div>
      <div class="value red">{{ cve_results | length }}</div>
    </div>
    <div class="card">
      <div class="label">HTTP Analysis</div>
      <div class="value yellow">{{ http_results | length }}</div>
    </div>
    <div class="card">
      <div class="label">Risk Score</div>
      <div class="value {% if meta.risk_level == 'CRITICAL' %}red{% elif meta.risk_level == 'HIGH' %}yellow{% elif meta.risk_level == 'MEDIUM' %}yellow{% else %}green{% endif %}">
        {{ meta.risk_score }}
      </div>
    </div>
  </div>

  <!-- Open ports table -->
  <h2>Open Ports</h2>
  {% if open_ports %}
  <table>
    <tr><th>Port</th><th>Service</th><th>Banner / Version</th></tr>
    {% for p in open_ports %}
    <tr>
      <td><span class="port-num">{{ p.port }}/tcp</span></td>
      <td><span class="service">{{ p.service }}</span></td>
      <td><span class="banner">{{ p.banner }}</span></td>
    </tr>
    {% endfor %}
  </table>
  {% else %}
  <p class="empty">No open ports found.</p>
  {% endif %}

  <!-- CVE results -->
  <h2>CVE Findings</h2>
  {% if cve_results %}
  {% for port, data in cve_results.items() %}
  <div style="margin-bottom:20px;">
    <div style="font-size:13px; color:var(--text-dim); margin-bottom:8px;">
      Port <span style="color:var(--cyan)">{{ port }}</span> —
      <strong style="color:var(--purple)">{{ data.service }} {{ data.version }}</strong>
    </div>
    <table>
      <tr><th>CVE ID</th><th>CVSS</th><th>Severity</th><th>Description</th></tr>
      {% for cve in data.cves %}
      <tr>
        <td><span class="cve-id">{{ cve.id }}</span></td>
        <td>
          {{ cve.score }}
          <div class="score-bar-wrap">
            <div class="score-bar" style="width: {{ (cve.score / 10 * 100)|int }}%"></div>
          </div>
        </td>
        <td><span class="severity-{{ cve.severity }}">{{ cve.severity }}</span></td>
        <td style="font-size:12px; color:var(--text-dim)">{{ cve.desc[:150] }}{% if cve.desc|length > 150 %}…{% endif %}</td>
      </tr>
      {% endfor %}
    </table>
  </div>
  {% endfor %}
  {% else %}
  <p class="empty">CVE scan was not performed or no results found.</p>
  {% endif %}

  <!-- HTTP header analysis -->
  <h2>HTTP Header Analysis</h2>
  {% if http_results %}
  {% for port, analysis in http_results.items() %}
  <div style="margin-bottom:24px;">
    <div style="display:flex; align-items:center; gap:12px; margin-bottom:12px;">
      <span style="color:var(--cyan); font-weight:600;">Port {{ port }}</span>
      <span class="http-score-ring"
        style="border-color: {% if analysis.score >= 80 %}var(--green){% elif analysis.score >= 50 %}var(--yellow){% else %}var(--red){% endif %};
               color:         {% if analysis.score >= 80 %}var(--green){% elif analysis.score >= 50 %}var(--yellow){% else %}var(--red){% endif %}">
        {{ analysis.score }}
      </span>
      <span style="color:var(--text-dim); font-size:12px;">security score / 100</span>
    </div>
    {% if analysis.missing %}
    <div style="margin-bottom:8px; font-size:12px; color:var(--text-dim);">Missing Headers:</div>
    <table>
      <tr><th>Header</th><th>Description</th><th>Risk</th></tr>
      {% for m in analysis.missing %}
      <tr>
        <td class="missing-header">✗ {{ m.header }}</td>
        <td style="font-size:12px">{{ m.desc }}</td>
        <td><span class="severity-{{ m.risk }}">{{ m.risk }}</span></td>
      </tr>
      {% endfor %}
    </table>
    {% endif %}
    {% set bad_headers = analysis.present | selectattr("bad") | list %}
    {% if bad_headers %}
    <div style="margin-top:10px; margin-bottom:8px; font-size:12px; color:var(--text-dim);">Information Disclosure:</div>
    <table>
      <tr><th>Header</th><th>Value</th><th>Note</th></tr>
      {% for p in bad_headers %}
      <tr>
        <td class="bad-header">⚠ {{ p.header }}</td>
        <td style="font-family:monospace; font-size:12px">{{ p.value[:80] }}</td>
        <td style="font-size:12px; color:var(--text-dim)">{{ p.desc }}</td>
      </tr>
      {% endfor %}
    </table>
    {% endif %}
  </div>
  {% endfor %}
  {% else %}
  <p class="empty">No HTTP ports found or analysis was skipped.</p>
  {% endif %}

  <!-- OS info -->
  <h2>Operating System Estimate</h2>
  <div class="os-info">{{ meta.os_estimate }}</div>

</div>

<div class="footer">
  Scaptanax v3 — ArchJúnior Edition &nbsp;|&nbsp;
  Use only on authorized systems &nbsp;|&nbsp;
  {{ meta.timestamp }}
</div>

</body>
</html>
"""


def save_html_report(
    target_ip:    str,
    open_ports:   list,
    cve_results:  dict,
    http_results: dict,
    os_info:      str,
    risk_level:   str,
    risk_score:   int,
    output_file:  str,
) -> None:
    """Writes all scan results to a styled HTML report."""
    if not JINJA2_AVAILABLE:
        print(Fore.YELLOW + "[!] jinja2 not found — HTML report skipped. pip install jinja2")
        return

    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    ports_data = [
        {"port": p[0], "service": p[1], "banner": p[2]}
        for p in open_ports
    ]

    http_str = {str(k): v for k, v in http_results.items()}
    cve_str  = {str(k): v for k, v in cve_results.items()}

    context = {
        "meta": {
            "tool":       "Scaptanax v3",
            "target":     target_ip,
            "timestamp":  timestamp,
            "risk_level": risk_level,
            "risk_score": risk_score,
            "os_estimate": os_info,
        },
        "open_ports":   ports_data,
        "cve_results":  cve_str,
        "http_results": http_str,
    }

    try:
        env      = jinja2.Environment(autoescape=True)
        template = env.from_string(HTML_TEMPLATE)
        html     = template.render(**context)

        with open(output_file, "w", encoding="utf-8") as f:
            f.write(html)
        print(Fore.CYAN + f"[*] HTML report saved → {output_file}")

    except OSError as e:
        print(Fore.RED + f"[!] Failed to save HTML report: {e}")
    except jinja2.TemplateError as e:
        print(Fore.RED + f"[!] Jinja2 template error: {e}")

def save_report(
    target_ip:    str,
    open_ports:   list,
    cve_results:  dict,
    http_results: dict,
    os_info:      str,
    risk_level:   str,
    risk_score:   int,
    output_format: str,
    output_file:  str,
) -> None:
    timestamp = datetime.datetime.now().isoformat()

    try:
        if output_format == "json":
            report = {
                "meta": {
                    "tool":       "Scaptanax v3",
                    "target":     target_ip,
                    "timestamp":  timestamp,
                    "risk_level": risk_level,
                    "risk_score": risk_score,
                    "os_estimate": os_info,
                },
                "open_ports": [
                    {"port": p[0], "service": p[1], "banner": p[2]}
                    for p in open_ports
                ],
                "cve_results":  {str(k): v for k, v in cve_results.items()},
                "http_results": {str(k): v for k, v in http_results.items()},
            }
            with open(output_file, "w", encoding="utf-8") as f:
                json.dump(report, f, ensure_ascii=False, indent=2)
            print(Fore.CYAN + f"[*] JSON report saved → {output_file}")

        elif output_format == "csv":
            with open(output_file, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["Port", "Service", "Banner", "Target", "Timestamp"])
                for p in open_ports:
                    writer.writerow([p[0], p[1], p[2], target_ip, timestamp])
            print(Fore.CYAN + f"[*] CSV report saved → {output_file}")

    except OSError as e:
        print(Fore.RED + f"[!] Failed to save report: {e}")

def scan_single_target(
    target:       str,
    args:         argparse.Namespace,
    ports:        list,
    timing:       dict,
    thread_count: int,
    use_syn:      bool,
) -> dict:
    """
    Performs a full scan on a single target.
    Returns results as a dict.
    """
    try:
        target_ip = socket.gethostbyname(target)
        if target_ip != target:
            print(Fore.CYAN + f"[*] DNS: {target} → {target_ip}")
    except socket.gaierror as e:
        print(Fore.RED + f"[!] Could not resolve {target}: {e}")
        return {}

    print(Fore.CYAN + f"\n{'═'*68}")
    print(Fore.CYAN + f"  TARGET: {target_ip}")
    print(Fore.CYAN + f"{'═'*68}")
    print(Fore.CYAN + f"  Method  : {'SYN Stealth' if use_syn else 'TCP Connect'}")
    print(Fore.CYAN + f"  Threads : {thread_count}  |  Timeout: {timing['timeout']}s")
    print(Fore.CYAN + f"  Started : {datetime.datetime.now().strftime('%H:%M:%S')}\n")

    if use_syn:
        def scan_func(ip, port, timeout):
            return syn_scan(ip, port, timeout, aggressive=args.sV)
    else:
        def scan_func(ip, port, timeout):
            return tcp_connect_scan(ip, port, timeout, aggressive=args.sV)

    open_ports = []
    lock       = Lock()

    with ThreadPoolExecutor(max_workers=thread_count) as executor:
        futures = {
            executor.submit(scan_func, target_ip, p, timing["timeout"]): p
            for p in ports
        }
        for future in tqdm(
            as_completed(futures),
            total=len(ports),
            desc="Scanning",
            colour="cyan",
            unit="port",
            leave=True,
        ):
            try:
                result = future.result()
            except Exception:
                continue
            if result is not None:
                port, service, banner = result
                with lock:
                    open_ports.append([port, service, banner])
                tqdm.write(
                    Fore.GREEN + f"[+] {port:5d}/tcp  OPEN  →  {service:<15}  {banner}"
                )

    open_ports.sort(key=lambda x: x[0])

    os_estimate = (
        os_fingerprint(target_ip) if args.O
        else "Skipped (enable with -O)"
    )

    cve_results = {}
    if args.cve and open_ports:
        cve_results = run_cve_scan(open_ports)

    http_results = {}
    if args.headers:
        http_results = run_http_header_scan(target_ip, open_ports, timing["timeout"])

    risk_level, risk_score = calculate_risk_level(
        open_ports, cve_results, os_estimate, http_results
    )
    r_color = risk_color(risk_level)

    print(Fore.CYAN + f"\n{'═'*68}")
    print(Fore.CYAN + "  SCAN RESULTS")
    print(Fore.CYAN + f"{'═'*68}")

    if open_ports:
        print(tabulate(
            open_ports,
            headers=["Port", "Service", "Banner / Version"],
            tablefmt="rounded_grid",
            colalign=("right", "left", "left"),
        ))
    else:
        print(Fore.YELLOW + "  No open ports found.")

    print()
    print(Fore.CYAN + f"  OS Estimate   : {os_estimate}")
    print(r_color   + f"  Risk Level    : {risk_level} (score: {risk_score})")
    print(Fore.CYAN + f"  Open Ports    : {len(open_ports)}")
    print(Fore.CYAN + f"  Finished      : {datetime.datetime.now().strftime('%H:%M:%S')}")
    print(Fore.CYAN + f"{'═'*68}")

    return {
        "target_ip":    target_ip,
        "open_ports":   open_ports,
        "cve_results":  cve_results,
        "http_results": http_results,
        "os_estimate":  os_estimate,
        "risk_level":   risk_level,
        "risk_score":   risk_score,
    }

def port_scanner(args: argparse.Namespace) -> None:
    print(Fore.CYAN + BANNER)
    print(Fore.RED  + "Scaptanax v3 — ArchJúnior Edition\n")

    if not SCAPY_AVAILABLE:
        print(Fore.YELLOW + "[!] scapy not found — SYN scan and OS fingerprint disabled.")
    if not JINJA2_AVAILABLE:
        print(Fore.YELLOW + "[!] jinja2 not found — HTML report disabled. pip install jinja2")

    targets = parse_targets(args.target)
    if len(targets) > 1:
        print(Fore.CYAN + f"[*] Subnet scan: {len(targets)} hosts targeted")

    ports        = parse_ports(args.ports)
    timing       = get_timing_params(args.timing)
    thread_count = min(args.threads, MAX_THREADS)

    if args.threads > MAX_THREADS:
        print(Fore.YELLOW + f"[!] Thread count capped at {MAX_THREADS}.")

    use_syn = args.sS and SCAPY_AVAILABLE and os.geteuid() == 0
    if args.sS and not use_syn:
        reason = "scapy not available" if not SCAPY_AVAILABLE else "no root privileges"
        print(Fore.YELLOW + f"[!] SYN scan disabled ({reason}) — falling back to TCP Connect.")

    all_results = []
    for target in targets:
        result = scan_single_target(target, args, ports, timing, thread_count, use_syn)
        if result:
            all_results.append(result)

    if not all_results:
        print(Fore.RED + "\n[!] No targets could be scanned.")
        return

    if args.output:
        for result in all_results:
            base, ext = os.path.splitext(args.output)
            suffix = f"_{result['target_ip']}" if len(all_results) > 1 else ""
            out_file = f"{base}{suffix}{ext}" if ext else f"{args.output}{suffix}"

            if out_file.lower().endswith(".html"):
                save_html_report(
                    result["target_ip"],
                    result["open_ports"],
                    result["cve_results"],
                    result["http_results"],
                    result["os_estimate"],
                    result["risk_level"],
                    result["risk_score"],
                    out_file,
                )
            elif out_file.lower().endswith(".csv"):
                save_report(
                    result["target_ip"],
                    result["open_ports"],
                    result["cve_results"],
                    result["http_results"],
                    result["os_estimate"],
                    result["risk_level"],
                    result["risk_score"],
                    "csv",
                    out_file,
                )
            else:
                save_report(
                    result["target_ip"],
                    result["open_ports"],
                    result["cve_results"],
                    result["http_results"],
                    result["os_estimate"],
                    result["risk_level"],
                    result["risk_score"],
                    "json",
                    out_file,
                )

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Scaptanax — Advanced Port Scanner & Security Analysis Tool",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python scaptanax.py -t 192.168.1.1\n"
            "  python scaptanax.py -t 192.168.1.0/24 -p 22,80,443\n"
            "  python scaptanax.py -t example.com -A --cve --headers -o report.html\n"
            "  python scaptanax.py -t 10.0.0.1 --timing 4 -sV -o results.json\n"
            "\n"
            "Environment variables:\n"
            "  NVD_API_KEY  →  NVD API key (removes rate limit)\n"
            "                  https://nvd.nist.gov/developers/request-an-api-key\n"
        ),
    )
    parser.add_argument(
        "-t", "--target",
        required=True,
        metavar="TARGET",
        help="Target: IP, hostname, or CIDR (e.g. 192.168.1.0/24)",
    )
    parser.add_argument(
        "-p", "--ports",
        default="1-1024",
        metavar="PORTS",
        help="Port range\nExamples: 80  |  1-1024  |  22,80,443  |  1-100,8080",
    )
    parser.add_argument(
        "--threads",
        type=int, default=100, metavar="N",
        help=f"Thread count (default: 100, max: {MAX_THREADS})",
    )
    parser.add_argument(
        "-sS",
        dest="sS", action="store_true",
        help="SYN Stealth Scan — requires root/sudo",
    )
    parser.add_argument(
        "-O",
        dest="O", action="store_true",
        help="OS Fingerprint — requires root/sudo",
    )
    parser.add_argument(
        "-sV",
        dest="sV", action="store_true",
        help="Aggressive service enumeration — probes ports that don't respond",
    )
    parser.add_argument(
        "--cve",
        action="store_true",
        help="CVE scan — queries detected services against the NVD database",
    )
    parser.add_argument(
        "--headers",
        action="store_true",
        help="HTTP header analysis — reports missing security headers",
    )
    parser.add_argument(
        "--timing",
        type=int, default=3, choices=range(0, 6), metavar="[0-5]",
        help=(
            "Timing profile:\n"
            "  0=Paranoid 1=Sneaky 2=Polite 3=Normal 4=Aggressive 5=Insane\n"
            "  (default: 3)"
        ),
    )
    parser.add_argument(
        "-A", "--aggressive",
        dest="aggressive", action="store_true",
        help="Aggressive mode: SYN + OS + sV (requires root)",
    )
    parser.add_argument(
        "-o", "--output",
        metavar="FILE",
        help=(
            "Save results to file:\n"
            "  report.html  →  Visual HTML report\n"
            "  results.json →  JSON format\n"
            "  results.csv  →  CSV format"
        ),
    )
    return parser

if __name__ == "__main__":
    parser = build_parser()
    args   = parser.parse_args()

    if args.aggressive:
        args.sS = True
        args.O  = True
        args.sV = True

    port_scanner(args)
