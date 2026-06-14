# netlookscan — NetScan v2

A self-hosted dashboard for discovering, fingerprinting, and monitoring devices on your local network. A fast multithreaded scanner core feeds a live web UI over Server-Sent Events, with optional deep enrichment, risk scoring, history, and change tracking backed by SQLite.

> ⚠️ **Use responsibly.** This tool performs active scanning — ping sweeps, port scans, banner grabbing, SNMP/NetBIOS queries, and (in deep mode) default-credential checks. Only run it against networks and devices you own or are explicitly authorized to test.

## Features

- **Live dashboard** — dark-themed web UI, streamed scan results in real time
- **Ping sweep** of a configurable subnet and host range
- **Fingerprinting** — hostname (reverse DNS), OS guess (TTL heuristic), MAC + vendor (ARP/OUI lookup), open ports (~30 common services), and inferred device type with icons
- **Deep scan mode** — banner grabbing (SSH, FTP, SMTP, Telnet), HTTP title/Server header, SNMP `sysDescr`/uptime, NetBIOS name, default-credential checks, and CVE lookups (NVD, cached)
- **Risk scoring** — flags risky open services (Telnet, FTP, VNC, RDP, exposed SMB, etc.)
- **Deep port scan** — scan a custom port range on a single host
- **Scan history** — every scan persisted to SQLite, browsable from the UI
- **Known hosts + change detection** — tracks new/lost hosts and newly opened/closed ports across scans
- **Continuous monitoring** — background scans on a configurable interval
- **Webhooks** — POST notifications when changes are detected
- **Traceroute** and **Wake-on-LAN** from the dashboard

## Project Structure

| File               | Purpose                                                                 |
|--------------------|--------------------------------------------------------------------------|
| `server.py`        | Flask backend — REST + SSE API, scan orchestration, monitoring loop      |
| `scanner_core.py`  | Ping sweep, TTL-based OS guess, ARP/vendor lookup, port scan, device-type inference |
| `enrichment.py`    | Deep fingerprinting — banners, HTTP/SNMP/NetBIOS, CVE lookup, risk scoring, traceroute, Wake-on-LAN |
| `db.py`            | SQLite persistence — scans, hosts, ports, known hosts, change log, CVE cache |
| `netscanner.html`  | Web dashboard front end                                                   |
| `launch.sh`        | Installs dependencies and starts the server                              |

## Requirements

- Python 3.10+
- Flask, Flask-CORS
- `ping`, `arp`, and `traceroute`/`tracert` available on the system PATH
- Root/administrator privileges are recommended — needed for reliable ARP cache access, raw ICMP, and SNMP/NetBIOS UDP queries on some systems

## Quick Start

```bash
chmod +x launch.sh
./launch.sh
```

Then open **http://localhost:5000** in your browser.

`launch.sh` installs Flask and Flask-CORS via `apt` if they're missing, then runs `server.py` with `sudo` (required for ARP and raw socket access on most systems).

## Using the Dashboard

1. Enter the subnet and host range to scan (defaults to `192.168.1`, `0–255`)
2. Optionally enable **Deep Scan** for banner grabbing, SNMP/NetBIOS queries, CVE lookups, and default-credential checks
3. Start the scan — results stream in live, with each host's hostname, OS guess, MAC/vendor, open ports, device type, and risk score
4. Browse **scan history**, **known hosts**, and the **change log** from the side panels
5. Click a host for details, traceroute, Wake-on-LAN, or a deep port scan
6. Enable **continuous monitoring** to re-scan automatically on an interval, and optionally configure a webhook to receive change notifications

## API Reference

| Endpoint                          | Method | Description                              |
|------------------------------------|--------|--------------------------------------------|
| `/api/scan?subnet=...&end=...&deep=1` | GET    | SSE stream of a live scan                |
| `/api/status`                      | GET    | Current scan status                       |
| `/api/stop`                        | POST   | Stop the running scan                     |
| `/api/last`                        | GET    | Results from the most recent scan         |
| `/api/history`                     | GET    | List of past scans                        |
| `/api/history/<scan_id>/hosts`     | GET    | Hosts found in a given scan               |
| `/api/known`                       | GET    | All known hosts                           |
| `/api/changes`                     | GET    | Change log (new/lost hosts, port changes) |
| `/api/stats`                       | GET    | Summary statistics                        |
| `/api/deepscan?ip=...&min=...&max=...` | GET | SSE stream of a full port range scan on one host |
| `/api/traceroute?ip=...`           | GET    | Traceroute to a host                      |
| `/api/wol`                         | POST   | Send a Wake-on-LAN packet (`{"mac": "..."}`) |
| `/api/cve?q=...`                   | GET    | CVE lookup for a banner/product string    |
| `/api/webhook`                     | GET/POST | Get or set the change-notification webhook URL |
| `/api/monitor/status`              | GET    | Continuous monitoring status              |
| `/api/monitor/start`               | POST   | Start monitoring (`{"interval": 300}`)    |
| `/api/monitor/stop`                | POST   | Stop monitoring                           |

## Data Storage

A SQLite database (`netscan.db`) is created automatically alongside the scripts and stores:

- `scans` — one row per scan run
- `hosts` / `ports` — fingerprint results per scan
- `known_hosts` — latest state of every device ever seen
- `changes` — detected new/lost hosts and port changes
- `cve_cache` — cached NVD lookups

## Limitations

- TTL-based OS guessing is a heuristic and not always accurate
- MAC/vendor lookup only works for devices on the same L2 segment (relies on the local ARP cache) and is limited to the OUIs in `OUI_TABLE`
- SNMP, NetBIOS, and HTTP enrichment depend on those services being enabled on the target device
- Deep scan, default-credential checks, and full port-range scans are noticeably more invasive — use only for auditing your own devices

## License

Free to use but cite me if possible. If you make a 1000 dollars from this, give me 1 dollar :)