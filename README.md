# netlookscan

A multithreaded Python tool that sweeps a `/24` subnet for live hosts and fingerprints each one — hostname, OS guess, MAC/vendor, open ports, and inferred device type.

> **Use responsibly.** Only scan networks you own or have explicit permission to scan.

## Features

- Concurrent ping sweep across the entire subnet
- Reverse DNS hostname lookup
- OS guess via TTL heuristic (Linux/macOS/Android vs. Windows vs. network gear)
- MAC address and vendor lookup (OUI table) from the local ARP cache
- Fast scan of ~30 common service ports
- Device type inference (router, printer, NAS, IoT, server, VM, etc.) based on ports, hostname, and vendor

## Requirements

- Python 3.10+
- `ping` and `arp` available on the system PATH (default on Windows, Linux, and macOS)
- MAC/vendor lookup only works for devices on the same local network segment (same L2/broadcast domain) — it relies on the host's ARP cache
- Reading the ARP table may require elevated privileges on some systems

## Usage

```bash
python3 scanner_core.py
```

The scan runs in two phases:

1. **Ping sweep** — quickly identifies which hosts in the subnet are alive
2. **Fingerprinting** — for each live host, gathers hostname, OS guess, MAC/vendor, open ports, and device type

## Configuration

Edit the constants near the top of the script:

| Variable       | Description                              | Default     |
|-----------------|-------------------------------------------|-------------|
| `SUBNET`        | Base subnet (first 3 octets)              | `192.168.1` |
| `START` / `END` | Host octet range to scan                  | `0` – `255` |
| `MAX_WORKERS`   | Concurrent threads for the ping sweep     | `50`        |
| `PING_TIMEOUT`  | Timeout per ping (seconds)                | `1`         |
| `PING_COUNT`    | Packets sent per host                     | `1`         |
| `PORT_TIMEOUT`  | Timeout per port probe (seconds)          | `0.5`       |
| `COMMON_PORTS`  | Dict of `{port: service-label}` to probe  | ~30 ports   |

The `OUI_TABLE` dict maps MAC address prefixes to vendor names and can be extended with additional OUIs as needed.

## Example Output

```
============================================================
  Subnet Scanner + Fingerprint — 192.168.1.0–192.168.1.255
  Started : 2026-06-14 10:30:00
  Threads : 50  |  Ping timeout : 1s  |  Port timeout : 0.5s
============================================================
  Phase 1 — Pinging all hosts …

  [  1/256]  192.168.1.1        ✔  UP
  [  2/256]  192.168.1.2        ✘  DOWN
  ...

  Phase 1 done — 5 host(s) up.

============================================================
  Phase 2 — Fingerprinting live hosts …

  [1/5]  Fingerprinting 192.168.1.1 …
  ...

============================================================
  SCAN REPORT
============================================================

  IP          : 192.168.1.1
  Device Type : 🌐 Network / Router
  Hostname    : router.lan
  OS (TTL=64) : Linux / Android / macOS
  MAC         : cc:9e:a2:11:22:33   Vendor: Ubiquiti
  Open Ports  : 22/SSH, 80/HTTP, 443/HTTPS
  ────────────────────────────────────────────────────

  Total live hosts : 5
  Scan finished   : 2026-06-14 10:30:42
```

## Limitations

- TTL-based OS guessing is a heuristic and not always accurate
- Vendor lookup is limited to the OUIs included in `OUI_TABLE`
- Port scanning is limited to the ports listed in `COMMON_PORTS`

## License

MIT

## License

Free to use but cite me if possible. If you make a 1000 dollars from this, gvie me 1 dollar :)