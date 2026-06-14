#!/usr/bin/env python3
"""
Subnet Scanner — 192.168.1.0/24
For every live host, fingerprints:
  • Hostname       (reverse DNS)
  • OS guess       (TTL heuristic from ping output)
  • MAC / Vendor   (ARP table — works on same L2 segment)
  • Open ports     (fast scan of ~25 common ports)
  • Device type    (inferred from open ports + hostname keywords)
"""

import subprocess, platform, socket, re, os, csv
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

# ── Configuration ─────────────────────────────────────────────────────────────
SUBNET        = "192.168.1"
START         = 0
END           = 255
MAX_WORKERS   = 50
PING_TIMEOUT  = 1
PING_COUNT    = 1
PORT_TIMEOUT  = 0.5   # seconds per port probe
# Common ports to probe  (port: service-label)
COMMON_PORTS  = {
    21:   "FTP",
    22:   "SSH",
    23:   "Telnet",
    25:   "SMTP",
    53:   "DNS",
    80:   "HTTP",
    110:  "POP3",
    135:  "RPC",
    139:  "NetBIOS",
    143:  "IMAP",
    443:  "HTTPS",
    445:  "SMB",
    515:  "LPD/Print",
    548:  "AFP",
    554:  "RTSP",
    631:  "IPP/Print",
    993:  "IMAPS",
    1883: "MQTT",
    3306: "MySQL",
    3389: "RDP",
    5000: "UPnP/Dev",
    5900: "VNC",
    6443: "K8s API",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    8883: "MQTT-TLS",
    9100: "RAW-Print",
    9090: "Cockpit",
    10250:"Kubelet",
    49152:"UPnP",
}
# ──────────────────────────────────────────────────────────────────────────────


# ── MAC vendor prefix table (curated — common LAN, IoT, and consumer gear) ────
# Best-effort hand-curated subset. For comprehensive, authoritative coverage,
# download the full IEEE MA-L OUI registry from:
#     https://standards-oui.ieee.org/oui/oui.csv
# and save it as "oui.csv" next to this script — it's loaded automatically
# below and merged in, with the curated names here taking priority.
OUI_TABLE = {
    # Virtualization / hypervisors
    "00:50:56": "VMware",       "00:0c:29": "VMware",       "00:1c:42": "Parallels",
    "08:00:27": "VirtualBox",   "52:54:00": "QEMU/KVM",     "00:16:3e": "Xen",

    # Raspberry Pi
    "b8:27:eb": "Raspberry Pi", "dc:a6:32": "Raspberry Pi", "e4:5f:01": "Raspberry Pi",

    # Apple
    "28:cd:c1": "Apple",        "f0:18:98": "Apple",        "3c:22:fb": "Apple",
    "ac:de:48": "Apple",

    # Google / Nest
    "00:1a:11": "Google",       "f4:f5:d8": "Google",       "54:60:09": "Google",
    "94:b4:0f": "Google",
    "18:b4:30": "Nest/Google",  "64:16:66": "Nest/Google",

    # Amazon
    "b0:34:95": "Amazon Echo",  "fc:65:de": "Amazon Echo",  "68:37:e9": "Amazon Echo",

    # Samsung
    "5c:0a:5b": "Samsung",      "8c:77:12": "Samsung",      "bc:14:85": "Samsung",

    # Smart home / IoT
    "00:17:88": "Philips Hue",  "ec:b5:fa": "Philips Hue",
    "5c:aa:fd": "Sonos",        "00:0e:58": "Sonos",
    "94:10:3e": "Belkin/Wemo",  "ec:1a:59": "Belkin/Wemo",
    "b8:3e:59": "Roku",         "dc:3a:5e": "Roku",
    "00:19:fb": "Vizio",
    "24:6f:28": "Espressif (ESP32/ESP8266 IoT)",
    "24:0a:c4": "Espressif (ESP32/ESP8266 IoT)",
    "30:ae:a4": "Espressif (ESP32/ESP8266 IoT)",
    "84:cc:a8": "Espressif (ESP32/ESP8266 IoT)",

    # Mobile devices
    "64:09:80": "Xiaomi",       "f0:b4:29": "Xiaomi",       "00:e0:fc": "Huawei",
    "10:68:3f": "LG Electronics",

    # Game consoles
    "00:50:f2": "Microsoft",    "00:13:a9": "Sony",
    "00:09:bf": "Nintendo",     "00:1f:32": "Nintendo",

    # Networking
    "cc:9e:a2": "Ubiquiti",     "04:18:d6": "Ubiquiti",     "f4:92:bf": "Ubiquiti",
    "00:1f:16": "Netgear",      "20:4e:7f": "Netgear",
    "c0:ff:d4": "TP-Link",      "50:c7:bf": "TP-Link",      "b0:be:76": "TP-Link",
    "74:da:38": "Edimax",
    "00:18:e7": "Cisco",        "00:1e:14": "Cisco",        "58:97:bd": "Cisco",
    "00:13:d4": "D-Link",       "1c:7e:e5": "D-Link",
    "00:0c:42": "MikroTik",     "4c:5e:0c": "ASUS",

    # PCs / servers / NAS
    "00:30:48": "Supermicro",   "ac:1f:6b": "Supermicro",
    "00:26:b9": "Dell",         "14:18:77": "Dell",         "f8:db:88": "Dell",
    "00:1b:21": "Intel NIC",    "8c:ec:4b": "Intel NIC",
    "00:e0:4c": "Realtek",
    "f8:1a:67": "HP",           "3c:d9:2b": "HP",           "00:21:5a": "HP",
    "b8:ac:6f": "HP",
    "00:11:32": "Synology",
}


def _load_ieee_oui(filename: str = "oui.csv") -> dict[str, str]:
    """
    Optionally load the full IEEE MA-L OUI registry for comprehensive vendor
    lookups (~35k entries). Download once from:
        https://standards-oui.ieee.org/oui/oui.csv
    and place it next to this script as 'oui.csv'. Returns {} if not found,
    so this stays fully optional and works offline either way.
    """
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), filename)
    table: dict[str, str] = {}
    if not os.path.exists(path):
        return table
    try:
        with open(path, newline="", encoding="utf-8") as f:
            for row in csv.DictReader(f):
                assignment = (row.get("Assignment") or "").strip().upper()
                org = (row.get("Organization Name") or "").strip()
                if len(assignment) == 6 and org:
                    prefix = ":".join(assignment[i:i + 2] for i in range(0, 6, 2))
                    table[prefix] = org
    except Exception:
        pass
    return table


# Merge: full IEEE registry (if oui.csv is present) as the base, with the
# curated OUI_TABLE above taking priority for friendlier, more specific names.
_OUI_LOOKUP: dict[str, str] = _load_ieee_oui()
_OUI_LOOKUP.update({k.upper(): v for k, v in OUI_TABLE.items()})


def oui_vendor(mac: str) -> str:
    """Look up vendor from the first 3 octets of a MAC address (O(1))."""
    if not mac:
        return "Unknown"
    return _OUI_LOOKUP.get(mac[:8].upper(), "Unknown")


# ── Ping ──────────────────────────────────────────────────────────────────────
def build_ping_cmd(ip):
    sys = platform.system().lower()
    if sys == "windows":
        return ["ping", "-n", str(PING_COUNT), "-w", str(PING_TIMEOUT * 1000), ip]
    return ["ping", "-c", str(PING_COUNT), "-W", str(PING_TIMEOUT), ip]

def ping(ip: str) -> dict:
    cmd = build_ping_cmd(ip)
    try:
        r = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           timeout=PING_TIMEOUT + 1)
        alive = r.returncode == 0
        ttl   = parse_ttl(r.stdout.decode(errors="ignore")) if alive else None
    except Exception:
        alive, ttl = False, None
    return {"ip": ip, "alive": alive, "ttl": ttl}

def parse_ttl(ping_output: str) -> int | None:
    """Extract TTL value from ping stdout."""
    m = re.search(r"[Tt][Tt][Ll]=(\d+)", ping_output)
    return int(m.group(1)) if m else None

def ttl_to_os(ttl: int | None) -> str:
    """Heuristic OS guess from TTL."""
    if ttl is None:
        return "Unknown"
    if ttl <= 64:
        return "Linux / Android / macOS"
    if ttl <= 128:
        return "Windows"
    if ttl <= 255:
        return "Cisco / Network device"
    return "Unknown"


# ── Reverse DNS ───────────────────────────────────────────────────────────────
def reverse_dns(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""


# ── ARP (MAC address) ─────────────────────────────────────────────────────────
def get_mac_from_arp(ip: str) -> str:
    """
    Read the OS ARP cache after ping has populated it.
    Works on Linux, macOS, Windows.
    """
    sys = platform.system().lower()
    try:
        if sys == "windows":
            out = subprocess.check_output(["arp", "-a", ip],
                                          stderr=subprocess.DEVNULL,
                                          timeout=2).decode(errors="ignore")
            m = re.search(r"([\da-f]{2}[:-]){5}[\da-f]{2}", out, re.I)
        else:
            out = subprocess.check_output(["arp", "-n", ip],
                                          stderr=subprocess.DEVNULL,
                                          timeout=2).decode(errors="ignore")
            m = re.search(r"([\da-f]{2}:){5}[\da-f]{2}", out, re.I)
        if m:
            mac = m.group(0).lower()
            # Normalize separator to ':'
            mac = mac.replace("-", ":")
            return mac
    except Exception:
        pass
    return ""


# ── Port scan ─────────────────────────────────────────────────────────────────
def scan_ports(ip: str) -> dict[int, str]:
    """Return {port: label} for every open port in COMMON_PORTS."""
    open_ports = {}
    def probe(port):
        try:
            with socket.create_connection((ip, port), timeout=PORT_TIMEOUT):
                return port
        except Exception:
            return None

    with ThreadPoolExecutor(max_workers=len(COMMON_PORTS)) as ex:
        for port in [f for f in ex.map(probe, COMMON_PORTS) if f]:
            open_ports[port] = COMMON_PORTS[port]
    return open_ports


# ── Device-type inference ─────────────────────────────────────────────────────
def infer_device_type(hostname: str, open_ports: dict, os_guess: str, vendor: str) -> str:
    h  = hostname.lower()
    p  = set(open_ports.keys())
    v  = vendor.lower()

    # Network gear
    if any(k in h for k in ("router","gateway","gw","fw","firewall","switch","ap","ubnt","unifi")):
        return "🌐 Network / Router"
    if "cisco" in v or "ubiquiti" in v or "netgear" in v or "tp-link" in v or "d-link" in v:
        return "🌐 Network / Router"

    # Printers
    if p & {515, 631, 9100} or any(k in h for k in ("print","printer","hp","canon","epson","xerox","brother")):
        return "🖨  Printer"

    # NAS / storage
    if p & {548, 139, 445} and any(k in h for k in ("nas","synology","qnap","storage","diskstation")):
        return "💾 NAS / Storage"

    # Media / smart-TV
    if 554 in p or any(k in h for k in ("tv","roku","firetv","appletv","chromecast","kodi","plex","media")):
        return "📺 Media / Smart TV"

    # IoT / smart-home
    if 1883 in p or 8883 in p or any(k in h for k in ("cam","ipcam","sensor","esp","tasmota","shelly","hue","nest","ring")):
        return "💡 IoT / Smart Home"
    if "philips hue" in v or "amazon echo" in v or "nest" in v:
        return "💡 IoT / Smart Home"

    # Mobile
    if "android" in h or "iphone" in h or "pixel" in h:
        return "📱 Mobile Device"
    if "android" in os_guess.lower():
        return "📱 Mobile Device"

    # VMs / hypervisors
    if any(k in v for k in ("vmware","virtualbox","qemu","parallels")):
        return "🖥  Virtual Machine"

    # Servers
    if p & {22, 80, 443, 3306, 5432, 6443, 9090, 10250}:
        if 3389 not in p:
            return "🖥  Linux Server"
    if 3389 in p or 135 in p or 445 in p:
        return "💻 Windows PC / Server"

    # RDP-only Windows desktop
    if "windows" in os_guess.lower():
        return "💻 Windows PC"

    # macOS
    if "macos" in os_guess.lower() or "apple" in v:
        return "🍎 macOS Device"

    # Raspberry Pi
    if "raspberry" in v or "raspberry" in h:
        return "🍓 Raspberry Pi"

    # Linux generic
    if "linux" in os_guess.lower():
        return "🐧 Linux Host"

    return "❓ Unknown Device"


# ── Full fingerprint for one live host ───────────────────────────────────────
def fingerprint(ip: str, ttl: int | None) -> dict:
    hostname  = reverse_dns(ip)
    os_guess  = ttl_to_os(ttl)
    mac       = get_mac_from_arp(ip)
    vendor    = oui_vendor(mac) if mac else "Unknown"
    open_ports = scan_ports(ip)
    device_type = infer_device_type(hostname, open_ports, os_guess, vendor)

    return {
        "ip":          ip,
        "hostname":    hostname or "—",
        "os_guess":    os_guess,
        "ttl":         ttl,
        "mac":         mac or "—",
        "vendor":      vendor,
        "open_ports":  open_ports,
        "device_type": device_type,
    }


# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    ips   = [f"{SUBNET}.{i}" for i in range(START, END + 1)]
    total = len(ips)

    print("=" * 60)
    print(f"  Subnet Scanner + Fingerprint — {SUBNET}.{START}–{SUBNET}.{END}")
    print(f"  Started : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Threads : {MAX_WORKERS}  |  Ping timeout : {PING_TIMEOUT}s  |  Port timeout : {PORT_TIMEOUT}s")
    print(f" OUI table : {len(_OUI_LOOKUP)} entries {'(full IEEE registry loaded)' if len(_OUI_LOOKUP) > len(OUI_TABLE) else '(curated subset)'}")
    print("=" * 60)
    print("  Phase 1 — Pinging all hosts …\n")

    alive = []
    scanned = 0

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        futures = {ex.submit(ping, ip): ip for ip in ips}
        for f in as_completed(futures):
            res = f.result()
            scanned += 1
            status = "✔  UP" if res["alive"] else "✘  DOWN"
            print(f"  [{scanned:>3}/{total}]  {res['ip']:<18} {status}")
            if res["alive"]:
                alive.append(res)

    alive.sort(key=lambda x: int(x["ip"].split(".")[-1]))

    print(f"\n  Phase 1 done — {len(alive)} host(s) up.\n")

    if not alive:
        print("  No live hosts found.")
        return

    print("=" * 60)
    print("  Phase 2 — Fingerprinting live hosts …\n")

    results = []
    for i, host in enumerate(alive, 1):
        ip = host["ip"]
        print(f"  [{i}/{len(alive)}]  Fingerprinting {ip} …", flush=True)
        fp = fingerprint(ip, host["ttl"])
        results.append(fp)

    # ── Print full report ─────────────────────────────────────────────────────
    print("\n" + "=" * 60)
    print("  SCAN REPORT")
    print("=" * 60)

    for r in results:
        ports_str = ", ".join(
            f"{p}/{lbl}" for p, lbl in sorted(r["open_ports"].items())
        ) or "none found"

        print(f"""
  IP          : {r['ip']}
  Device Type : {r['device_type']}
  Hostname    : {r['hostname']}
  OS (TTL={r['ttl']}) : {r['os_guess']}
  MAC         : {r['mac']}   Vendor: {r['vendor']}
  Open Ports  : {ports_str}
  {"─"*52}""")

    print(f"\n  Total live hosts : {len(results)}")
    print(f"  Scan finished   : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")


if __name__ == "__main__":
    main()