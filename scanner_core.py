#!/usr/bin/env python3
"""
Ping all IP addresses in the 192.168.1.0/24 subnet (192.168.1.0 - 192.168.1.255)
Uses multithreading for fast concurrent scanning.
"""

import subprocess
import platform
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime


# ── Configuration ──────────────────────────────────────────────────────────────
SUBNET        = "192.168.1"   # Base subnet
START         = 0             # First host octet
END           = 255           # Last host octet
MAX_WORKERS   = 50            # Concurrent threads
PING_TIMEOUT  = 1             # Seconds to wait per ping
PING_COUNT    = 1             # Number of ping packets to send
# ───────────────────────────────────────────────────────────────────────────────


def build_ping_cmd(ip: str) -> list[str]:
    """Return the OS-appropriate ping command."""
    system = platform.system().lower()
    if system == "windows":
        # -n count  -w timeout_ms
        return ["ping", "-n", str(PING_COUNT), "-w", str(PING_TIMEOUT * 1000), ip]
    else:
        # Linux / macOS: -c count  -W timeout_s
        return ["ping", "-c", str(PING_COUNT), "-W", str(PING_TIMEOUT), ip]


def ping(ip: str) -> dict:
    """Ping a single IP and return a result dict."""
    cmd = build_ping_cmd(ip)
    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=PING_TIMEOUT + 1,
        )
        alive = result.returncode == 0
    except subprocess.TimeoutExpired:
        alive = False
    except Exception as e:
        alive = False

    return {"ip": ip, "alive": alive}


def main():
    ips = [f"{SUBNET}.{i}" for i in range(START, END + 1)]
    total = len(ips)

    print("=" * 55)
    print(f"  Subnet Scanner — {SUBNET}.{START} → {SUBNET}.{END}")
    print(f"  Started : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Threads : {MAX_WORKERS}  |  Timeout : {PING_TIMEOUT}s")
    print("=" * 55)

    alive_hosts = []
    dead_hosts  = []
    scanned     = 0

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(ping, ip): ip for ip in ips}

        for future in as_completed(futures):
            res = future.result()
            scanned += 1

            if res["alive"]:
                alive_hosts.append(res["ip"])
                status = "✔  UP"
            else:
                dead_hosts.append(res["ip"])
                status = "✘  DOWN"

            # Live progress line
            print(f"  [{scanned:>3}/{total}]  {res['ip']:<18} {status}")

    # ── Summary ────────────────────────────────────────────────────────────────
    # Sort results numerically
    alive_hosts.sort(key=lambda x: int(x.split(".")[-1]))

    print("\n" + "=" * 55)
    print(f"  Scan complete — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Total scanned : {total}")
    print(f"  Hosts UP      : {len(alive_hosts)}")
    print(f"  Hosts DOWN    : {len(dead_hosts)}")
    print("=" * 55)

    if alive_hosts:
        print("\n  Reachable hosts:")
        for ip in alive_hosts:
            print(f"    ✔  {ip}")
    else:
        print("\n  No reachable hosts found.")

    print()


if __name__ == "__main__":
    main()
