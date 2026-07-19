#!/usr/bin/env python3
"""
Mini Vulnerability Scanner
---------------------------
A lightweight, educational security scanner for systems/domains you OWN
or are AUTHORIZED to test. Checks:

  1. Open TCP ports (common services)
  2. Missing/weak HTTP security headers
  3. SSL/TLS certificate validity & expiry
  4. Basic server banner / version disclosure
  5. HTTP -> HTTPS redirect enforcement

Usage:
    python3 mini_vuln_scanner.py example.com
    python3 mini_vuln_scanner.py example.com --ports 21,22,80,443,3306
    python3 mini_vuln_scanner.py 192.168.1.10 --timeout 2

DISCLAIMER: Only scan hosts you own or have explicit written permission
to test. Unauthorized scanning may be illegal in your jurisdiction.
"""

import argparse
import socket
import ssl
import sys
import datetime
from urllib.parse import urlparse
import http.client

DEFAULT_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 3306, 3389, 8080, 8443]

COMMON_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
    3306: "MySQL", 3389: "RDP", 8080: "HTTP-Alt", 8443: "HTTPS-Alt"
}

RECOMMENDED_HEADERS = {
    "Strict-Transport-Security": "Protects against protocol downgrade attacks / cookie hijacking",
    "Content-Security-Policy": "Mitigates XSS and data injection attacks",
    "X-Content-Type-Options": "Prevents MIME-sniffing attacks (should be 'nosniff')",
    "X-Frame-Options": "Prevents clickjacking (should be 'DENY' or 'SAMEORIGIN')",
    "Referrer-Policy": "Controls how much referrer info is leaked",
    "Permissions-Policy": "Restricts access to browser features/APIs",
}

RISKY_PORTS = {
    21: "FTP often transmits credentials in plaintext",
    23: "Telnet transmits all data (incl. passwords) unencrypted",
    3306: "MySQL exposed to the internet is a common breach vector",
    3389: "RDP is a frequent target for brute-force/ransomware attacks",
    110: "POP3 (non-SSL) can leak credentials in plaintext",
    143: "IMAP (non-SSL) can leak credentials in plaintext",
}


class Finding:
    def __init__(self, severity, category, message):
        self.severity = severity  # HIGH, MEDIUM, LOW, INFO
        self.category = category
        self.message = message

    def __str__(self):
        colors = {
            "HIGH": "\033[91m", "MEDIUM": "\033[93m",
            "LOW": "\033[94m", "INFO": "\033[92m"
        }
        reset = "\033[0m"
        c = colors.get(self.severity, "")
        return f"[{c}{self.severity:6}{reset}] {self.category:12} {self.message}"


def scan_ports(host, ports, timeout):
    findings = []
    open_ports = []
    print(f"\n--- Port Scan ({len(ports)} ports) ---")
    for port in ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                result = s.connect_ex((host, port))
                if result == 0:
                    service = COMMON_SERVICES.get(port, "unknown")
                    open_ports.append(port)
                    print(f"  Port {port:5} OPEN  ({service})")
                    if port in RISKY_PORTS:
                        findings.append(Finding(
                            "MEDIUM", "Open Port",
                            f"Port {port} ({service}) open: {RISKY_PORTS[port]}"
                        ))
                    else:
                        findings.append(Finding(
                            "INFO", "Open Port",
                            f"Port {port} ({service}) is open"
                        ))
        except socket.gaierror:
            print(f"  Could not resolve host: {host}")
            sys.exit(1)
        except Exception:
            pass
    if not open_ports:
        print("  No open ports found in the scanned list.")
    return findings


def check_http_headers(host, timeout):
    findings = []
    print("\n--- HTTP Security Header Check ---")
    for scheme, port, conn_cls in [("https", 443, http.client.HTTPSConnection),
                                     ("http", 80, http.client.HTTPConnection)]:
        try:
            conn = conn_cls(host, port, timeout=timeout)
            conn.request("HEAD", "/")
            resp = conn.getresponse()
            headers = {k: v for k, v in resp.getheaders()}
            print(f"  [{scheme.upper()}] Response: {resp.status} {resp.reason}")

            server = headers.get("Server")
            if server:
                findings.append(Finding(
                    "LOW", "Info Disclosure",
                    f"Server header reveals: '{server}' ({scheme})"
                ))

            for hname, desc in RECOMMENDED_HEADERS.items():
                if hname not in headers:
                    findings.append(Finding(
                        "MEDIUM", "Missing Header",
                        f"[{scheme}] Missing '{hname}' — {desc}"
                    ))
                else:
                    print(f"    {hname}: present")

            if scheme == "http" and resp.status not in (301, 302, 307, 308):
                findings.append(Finding(
                    "HIGH", "No HTTPS Redirect",
                    "Port 80 does not redirect to HTTPS — traffic may be sent in plaintext"
                ))

            conn.close()
        except (socket.timeout, ConnectionRefusedError, OSError):
            print(f"  [{scheme.upper()}] Not reachable")
        except Exception as e:
            print(f"  [{scheme.upper()}] Error: {e}")
    return findings


def check_ssl_cert(host, timeout):
    findings = []
    print("\n--- SSL/TLS Certificate Check ---")
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                not_after = cert.get("notAfter")
                expiry = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                days_left = (expiry - datetime.datetime.utcnow()).days
                print(f"  Certificate expires: {expiry} ({days_left} days left)")

                if days_left < 0:
                    findings.append(Finding("HIGH", "SSL Cert", "Certificate has EXPIRED"))
                elif days_left < 14:
                    findings.append(Finding("HIGH", "SSL Cert", f"Certificate expires in {days_left} days"))
                elif days_left < 30:
                    findings.append(Finding("MEDIUM", "SSL Cert", f"Certificate expires in {days_left} days"))
                else:
                    findings.append(Finding("INFO", "SSL Cert", f"Certificate valid for {days_left} more days"))

                proto = ssock.version()
                print(f"  TLS Protocol: {proto}")
                if proto in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
                    findings.append(Finding("HIGH", "Weak TLS", f"Outdated protocol in use: {proto}"))
                else:
                    findings.append(Finding("INFO", "TLS Version", f"Using {proto}"))
    except ssl.SSLCertVerificationError as e:
        findings.append(Finding("HIGH", "SSL Cert", f"Certificate verification failed: {e.reason}"))
    except (socket.timeout, ConnectionRefusedError, OSError):
        print("  Port 443 not reachable — skipping SSL check")
    except Exception as e:
        print(f"  SSL check error: {e}")
    return findings


def print_summary(findings):
    print("\n" + "=" * 60)
    print("SCAN SUMMARY")
    print("=" * 60)
    if not findings:
        print("No findings.")
        return

    order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}
    findings.sort(key=lambda f: order.get(f.severity, 4))

    counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        counts[f.severity] += 1
        print(f)

    print("-" * 60)
    print(f"Total: {len(findings)}  |  HIGH: {counts['HIGH']}  "
          f"MEDIUM: {counts['MEDIUM']}  LOW: {counts['LOW']}  INFO: {counts['INFO']}")


def main():
    parser = argparse.ArgumentParser(description="Mini Vulnerability Scanner (authorized use only)")
    parser.add_argument("target", help="Hostname or IP address to scan (e.g. example.com)")
    parser.add_argument("--ports", help="Comma-separated list of ports to scan", default=None)
    parser.add_argument("--timeout", type=float, default=1.5, help="Socket timeout in seconds")
    parser.add_argument("--skip-ports", action="store_true", help="Skip port scanning")
    parser.add_argument("--skip-http", action="store_true", help="Skip HTTP header checks")
    parser.add_argument("--skip-ssl", action="store_true", help="Skip SSL/TLS checks")
    args = parser.parse_args()

    parsed = urlparse(args.target if "://" in args.target else f"//{args.target}")
    host = parsed.hostname or args.target

    print(f"Mini Vulnerability Scanner")
    print(f"Target: {host}")
    print("Only scan systems you own or are authorized to test.\n")

    ports = [int(p) for p in args.ports.split(",")] if args.ports else DEFAULT_PORTS

    all_findings = []
    if not args.skip_ports:
        all_findings += scan_ports(host, ports, args.timeout)
    if not args.skip_http:
        all_findings += check_http_headers(host, args.timeout)
    if not args.skip_ssl:
        all_findings += check_ssl_cert(host, args.timeout)

    print_summary(all_findings)


if __name__ == "__main__":
    main()
