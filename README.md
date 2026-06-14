# netlookscan

A lightweight, multithreaded subnet scanner written in Python. Pings every host in a `/24` subnet and reports which are up or down.

## Features

- Concurrent pings via `ThreadPoolExecutor`
- Cross-platform (Windows, Linux, macOS)
- Live progress output as hosts respond
- Summary of reachable hosts at the end

## Requirements

- Python 3.9+
- `ping` available on the system PATH (included by default on Windows, Linux, and macOS)

## Usage

```bash
python3 scanner_core.py
```

## Configuration

Edit the constants near the top of the script:

| Variable      | Description                  | Default       |
|----------------|-------------------------------|---------------|
| `SUBNET`       | Base subnet (first 3 octets)  | `192.168.1`   |
| `START` / `END`| Host octet range to scan      | `0` – `255`   |
| `MAX_WORKERS`  | Concurrent threads            | `50`          |
| `PING_TIMEOUT` | Timeout per ping (seconds)    | `1`           |
| `PING_COUNT`   | Packets sent per host         | `1`           |

## Example Output

```
=======================================================
  Subnet Scanner — 192.168.1.0 → 192.168.1.255
  Started : 2026-06-14 10:30:00
  Threads : 50  |  Timeout : 1s
=======================================================
  [  1/256]  192.168.1.1        ✔  UP
  [  2/256]  192.168.1.2        ✘  DOWN
  ...

=======================================================
  Scan complete — 2026-06-14 10:30:05
  Total scanned : 256
  Hosts UP      : 12
  Hosts DOWN    : 244
=======================================================

  Reachable hosts:
    ✔  192.168.1.1
    ✔  192.168.1.20
    ...
```

## License

Free to use but cite me if possible. If you make a 1000 dollars from this, gvie me 1 dollar :)