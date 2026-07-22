# Mini Vulnerability Scanner

A lightweight, educational Python tool for auditing basic security
misconfigurations on systems **you own or are explicitly authorized to test**.

> ⚠️ **Authorization required.** Only run this against hosts you own or have
> explicit written permission to test. Scanning systems without authorization
> may be illegal under laws like the U.S. Computer Fraud and Abuse Act or
> equivalent legislation in your country.

---

## 1. About / Topic

Web-facing systems are frequently compromised not through exotic zero-days
but through basic, well-known misconfigurations: open management ports left
exposed to the internet, missing HTTP security headers that would otherwise
stop common browser-based attacks, and outdated TLS/SSL settings that weaken
encrypted connections. This project is a small command-line tool that checks
for exactly these three categories of misconfiguration on a single target,
and produces a readable report a student, sysadmin, or hobbyist can use to
understand and improve their own server's security posture.

## 2. What It Does

Given a hostname or IP address, the tool runs three independent checks:

1. **Port scan** — attempts a TCP connection to a curated list of
   commonly-abused ports (SSH, Telnet, RDP, MySQL, PostgreSQL, Redis,
   MongoDB, etc.) and reports which ones are open and responding.
2. **HTTP security header audit** — requests the site over HTTPS (falling
   back to HTTP) and checks for six headers that meaningfully affect a
   browser's security posture, flagging any that are missing. It also flags
   if the server is leaking its software/version via the `Server` header.
3. **TLS/SSL check** — connects on port 443, checks which TLS protocol
   version was negotiated (flagging outdated ones like TLSv1/1.1), and
   checks the certificate's expiry date, warning if it's within 30 days
   of expiring.

Results print to the terminal in real time and can optionally be exported
as a structured JSON report for later reference or integration into other
tooling.

## 3. Files & File Purpose

| File | Purpose |
|---|---|
| `mini_vuln_scanner.py` | The main script — contains all scanning logic (ports, headers, TLS) and the CLI entry point. This is the only file needed to run the tool. |
| `README.md` | This document — usage instructions and project background. |
| `screenshot_scan.png` | Example terminal output showing the port scan and HTTP header check in progress. |
| `screenshot_summary.png` | Example terminal output showing the TLS check and final summary. |

## 4. How to Run

**Requirements:** Python 3.7+, no external dependencies (standard library only).

```bash
# Basic scan — runs all three checks with default ports
python3 mini_vuln_scanner.py example.com

# Scan only specific ports
python3 mini_vuln_scanner.py example.com --ports 22,80,443,8080

# Save the full structured results to a JSON file
python3 mini_vuln_scanner.py example.com --json report.json

# Skip individual checks
python3 mini_vuln_scanner.py example.com --skip-ports
python3 mini_vuln_scanner.py example.com --skip-headers
python3 mini_vuln_scanner.py example.com --skip-tls
```

## 5. Dataset / Test Target Note

This tool does not use or ship with any dataset — it performs live checks
against a target you specify at runtime. There is no bundled sample data.
For testing or demonstration purposes, it's common (and safe) to point it
at:
- `localhost` / `127.0.0.1` if you have a local web server running
- A domain or server you personally own
- Publicly documented test domains intended for this purpose (e.g.
  `example.com`, which is reserved by IANA for documentation/testing and
  is safe to query for illustrative HTTP/TLS checks — though it won't have
  open service ports to demonstrate the port-scan feature)

No real-world scan data is included in this repository; the example
screenshots use illustrative, mocked output for documentation purposes only.

## 6. Why These Choices

- **Python standard library only** — no `pip install` step, no dependency
  version conflicts, works anywhere Python 3 is installed. This keeps the
  tool portable and easy to audit (nothing hidden in a third-party package).
- **Detection only, no exploitation** — the tool reports what it finds
  (open ports, missing headers, weak TLS) but never attempts to exploit,
  brute-force, or gain unauthorized access to anything. This keeps it safe
  to hand to students/beginners and keeps its use unambiguously legal when
  run against authorized targets.
- **A curated, small port list rather than a full 1–65535 scan** — the
  chosen ports represent commonly-targeted/high-risk services. A narrower,
  purposeful list keeps scans fast and avoids the tool looking like (or
  behaving like) a heavier, more invasive scanning tool such as nmap.
  Users can override this list with `--ports` if they want to check
  something specific.
- **JSON export option** — printing to the terminal is good for a quick
  look, but JSON output lets the results be parsed by other scripts, stored
  for comparison over time, or attached to a report.
- **Short timeouts (2.5s) per check** — keeps the tool responsive and
  avoids long hangs on filtered/firewalled ports, at some cost to accuracy
  on very slow networks (see limitations below).

## 7. Known Limitations

- **No UDP scanning** — only TCP ports are checked; UDP-based services
  (like some DNS or SNMP configurations) aren't covered.
- **No stealth/evasion techniques** — this is a straightforward connect
  scan, not a SYN scan or similar, so it can't bypass firewalls, IDS, or
  rate-limiting, and is easily logged by the target.
- **Single-target, single-threaded** — no batch scanning of multiple hosts
  and no concurrency, so scanning many ports against a slow host can take a
  while.
- **HTTP header check assumes a standard web server response** — some
  non-standard server configurations, redirects, or WAFs may produce
  results that need manual double-checking.
- **TLS check only tests port 443** — servers running TLS on non-standard
  ports aren't automatically checked.
- **False negatives on filtered ports** — a firewall that silently drops
  packets (rather than actively refusing them) may cause a port to be
  reported as closed when it's actually filtered, not genuinely closed.
- **Not a replacement for professional tools** — this is intentionally
  a small, educational tool. For production security auditing, dedicated
  tools like `nmap`, `nikto`, `testssl.sh`, or a professional penetration
  test are more thorough and better maintained.

## License

MIT License — free to use, modify, and distribute.
