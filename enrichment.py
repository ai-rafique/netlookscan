#!/usr/bin/env python3
"""
enrichment.py — deep fingerprinting beyond ping+ports
  • Banner grabbing  (SSH, HTTP, FTP, SMTP, Telnet)
  • HTTP title + server header inspection
  • SNMP sysDescr / sysUpTime (UDP/161, community=public)
  • NetBIOS name query (UDP/137)
  • mDNS passive listener helper
  • CVE lookup via NVD API (cached in SQLite)
  • Default credential check (HTTP basic auth)
  • Wake-on-LAN magic packet sender
  • Risk scoring engine
"""

import socket, struct, ssl, re, json, time, urllib.request, urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

try:
    import db as _db
    _HAS_DB = True
except ImportError:
    _HAS_DB = False

BANNER_TIMEOUT = 2.0
HTTP_TIMEOUT   = 3.0
SNMP_TIMEOUT   = 1.5

# ── Banner grabbing ───────────────────────────────────────────────────────────
def grab_banner(ip: str, port: int, send: bytes = b"", timeout: float = BANNER_TIMEOUT) -> str:
    """Connect, optionally send bytes, read first 512 bytes of response."""
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            if send:
                s.sendall(send)
            data = s.recv(512)
            return data.decode(errors="replace").strip()
    except Exception:
        return ""

def grab_ssh_banner(ip: str) -> str:
    raw = grab_banner(ip, 22)
    # e.g. "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u2"
    if raw.startswith("SSH-"):
        return raw.split("\r")[0].split("\n")[0]
    return ""

def grab_ftp_banner(ip: str) -> str:
    raw = grab_banner(ip, 21)
    if raw.startswith("220"):
        return raw.split("\r")[0][:120]
    return ""

def grab_smtp_banner(ip: str) -> str:
    raw = grab_banner(ip, 25)
    if raw.startswith("220"):
        return raw.split("\r")[0][:120]
    return ""

def grab_telnet_banner(ip: str) -> str:
    # Telnet sends IAC bytes first — strip them, take printable text
    raw = grab_banner(ip, 23, timeout=1.5)
    clean = re.sub(r'[\xff][\xfb-\xfe].', '', raw)
    clean = re.sub(r'[^\x20-\x7e\n]', '', clean).strip()
    return clean[:80] if clean else ""

def grab_http_info(ip: str, port: int = 80, https: bool = False) -> dict:
    """Grab HTTP title and Server header."""
    result = {"title": "", "server": "", "powered_by": "", "status": 0, "url": ""}
    scheme = "https" if https else "http"
    url = f"{scheme}://{ip}:{port}/"
    result["url"] = url
    try:
        ctx = ssl.create_default_context() if https else None
        if ctx:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(url, headers={"User-Agent": "NetScan/2.0"})
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT, context=ctx) as resp:
            result["status"]    = resp.status
            result["server"]    = resp.headers.get("Server", "")
            result["powered_by"]= resp.headers.get("X-Powered-By", "")
            body = resp.read(4096).decode(errors="replace")
            m = re.search(r"<title[^>]*>([^<]{1,120})</title>", body, re.I)
            if m:
                result["title"] = m.group(1).strip()
    except Exception:
        pass
    return result

# ── SNMP ──────────────────────────────────────────────────────────────────────
def _snmp_get(ip: str, oid_encoded: bytes, community: str = "public") -> bytes:
    """Minimal SNMP v1 GET for a single OID."""
    def encode_oid(oid_str):
        parts = list(map(int, oid_str.split(".")))
        body  = bytes([40 * parts[0] + parts[1]])
        for p in parts[2:]:
            if p == 0:
                body += b'\x00'
            else:
                enc = []
                while p:
                    enc.insert(0, p & 0x7f)
                    p >>= 7
                for i, b in enumerate(enc):
                    body += bytes([b | (0x80 if i < len(enc)-1 else 0)])
        return bytes([0x06, len(body)]) + body

    def tlv(tag, val):
        return bytes([tag, len(val)]) + val

    comm = community.encode()
    oid_bytes = encode_oid(oid_encoded if isinstance(oid_encoded, str) else oid_encoded.decode())
    varbind  = tlv(0x30, tlv(0x05, b'') + oid_bytes)  # simplified
    pdu      = tlv(0xa0, b'\x02\x01\x00' + b'\x02\x01\x00' + b'\x02\x01\x00' + tlv(0x30, varbind))
    packet   = tlv(0x30, b'\x02\x01\x00' + tlv(0x04, comm) + pdu)
    return packet

def snmp_query(ip: str, community: str = "public") -> dict:
    """
    Query sysDescr (1.3.6.1.2.1.1.1.0) and sysUpTime (1.3.6.1.2.1.1.3.0).
    Returns {"desc": str, "uptime": str} or empty strings on failure.
    Uses a raw UDP approach compatible with most devices.
    """
    result = {"desc": "", "uptime": ""}
    # Build minimal SNMP v1 GetRequest for sysDescr
    def build_get(oid_parts, community="public", req_id=1):
        def ber_len(n):
            if n < 0x80: return bytes([n])
            b = n.to_bytes((n.bit_length()+7)//8, 'big')
            return bytes([0x80|len(b)]) + b
        def tlv(t, v):
            return bytes([t]) + ber_len(len(v)) + v
        parts = oid_parts
        oid_body = bytes([40*parts[0]+parts[1]])
        for p in parts[2:]:
            if p==0: oid_body+=b'\x00'
            else:
                enc=[]
                while p: enc.insert(0,p&0x7f); p>>=7
                for i,b in enumerate(enc): oid_body+=bytes([b|(0x80 if i<len(enc)-1 else 0)])
        oid_tlv = tlv(0x06, oid_body)
        varbind  = tlv(0x30, tlv(0x30, oid_tlv + b'\x05\x00'))
        pdu_body = tlv(0x02,req_id.to_bytes(1,'big')) + b'\x02\x01\x00'*2 + varbind
        pdu      = tlv(0xa0, pdu_body)
        msg      = tlv(0x30, b'\x02\x01\x00' + tlv(0x04,community.encode()) + pdu)
        return msg

    oids = {
        "desc":   [1,3,6,1,2,1,1,1,0],
        "uptime": [1,3,6,1,2,1,1,3,0],
    }
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(SNMP_TIMEOUT)
        for key, oid in oids.items():
            pkt = build_get(oid, community)
            sock.sendto(pkt, (ip, 161))
            try:
                data, _ = sock.recvfrom(1024)
                # Extract OctetString or TimeTicks value from response — simple heuristic
                # Find the value after the OID in the response
                text = data[data.rfind(b'\x04')+2:data.rfind(b'\x04')+102] if b'\x04' in data else b''
                val  = text.decode(errors="replace").strip() if text else ""
                if not val:
                    # Try TimeTicks for uptime
                    idx = data.rfind(b'\x43')
                    if idx >= 0 and key == "uptime":
                        n = int.from_bytes(data[idx+2:idx+6], 'big')
                        secs = n // 100
                        h, m, s = secs//3600, (secs%3600)//60, secs%60
                        val = f"{h}h {m}m {s}s"
                result[key] = val[:200]
            except socket.timeout:
                pass
        sock.close()
    except Exception:
        pass
    return result

# ── NetBIOS name query ────────────────────────────────────────────────────────
def netbios_query(ip: str) -> str:
    """Send a NetBIOS Name Service status request (UDP/137), return computer name."""
    try:
        req = (
            b'\xa4\x3e'          # Transaction ID
            b'\x00\x00'          # Flags: query
            b'\x00\x01'          # Questions: 1
            b'\x00\x00\x00\x00\x00\x00'  # Answer/Auth/Additional RRs
            b'\x20'              # Name length = 32
            b'CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'  # encoded wildcard *
            b'\x00'
            b'\x00\x21'          # Type: NBSTAT
            b'\x00\x01'          # Class: IN
        )
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(1.5)
        sock.sendto(req, (ip, 137))
        data, _ = sock.recvfrom(1024)
        sock.close()
        if len(data) > 57:
            num_names = data[56]
            names = []
            for i in range(num_names):
                offset = 57 + i * 18
                if offset + 15 > len(data):
                    break
                name = data[offset:offset+15].decode(errors="replace").strip()
                flags = data[offset+16:offset+18]
                if flags[0] & 0x80 == 0:  # not a group name
                    if name and name not in names:
                        names.append(name)
            return names[0] if names else ""
    except Exception:
        pass
    return ""

# ── CVE lookup ────────────────────────────────────────────────────────────────
def lookup_cves(product_version: str, max_results: int = 5) -> list[dict]:
    """
    Query NVD API for CVEs matching a product/version string.
    Results cached in SQLite for 24 hours.
    """
    if not product_version or len(product_version) < 4:
        return []

    # Normalise: "OpenSSH_9.2p1" → "OpenSSH 9.2"
    key = re.sub(r'[_/]', ' ', product_version).strip()
    key = re.sub(r'p\d+$', '', key).strip()  # strip patch suffix

    # Check cache
    if _HAS_DB:
        cached = _db.get_cve_cache(key)
        if cached:
            age = (datetime.now() - datetime.fromisoformat(cached["fetched_at"])).total_seconds()
            if age < 86400:  # 24 hours
                return cached["cves"]

    cves = []
    try:
        query = urllib.parse.urlencode({"keywordSearch": key, "resultsPerPage": max_results})
        url   = f"https://services.nvd.nist.gov/rest/json/cves/2.0?{query}"
        req   = urllib.request.Request(url, headers={"User-Agent": "NetScan/2.0"})
        with urllib.request.urlopen(req, timeout=8) as resp:
            data = json.loads(resp.read())
            for item in data.get("vulnerabilities", []):
                cve = item.get("cve", {})
                cve_id   = cve.get("id", "")
                desc_list = cve.get("descriptions", [])
                desc = next((d["value"] for d in desc_list if d["lang"]=="en"), "")
                metrics  = cve.get("metrics", {})
                cvss = 0.0
                for key_m in ("cvssMetricV31","cvssMetricV30","cvssMetricV2"):
                    if key_m in metrics and metrics[key_m]:
                        cvss = metrics[key_m][0].get("cvssData",{}).get("baseScore", 0.0)
                        break
                cves.append({
                    "id":    cve_id,
                    "score": cvss,
                    "desc":  desc[:200],
                    "severity": "CRITICAL" if cvss>=9 else "HIGH" if cvss>=7 else "MEDIUM" if cvss>=4 else "LOW",
                })
    except Exception:
        pass

    if _HAS_DB and cves:
        _db.set_cve_cache(key, cves)

    return cves

# ── Default credential check ──────────────────────────────────────────────────
DEFAULT_CREDS = [
    ("admin",    "admin"),
    ("admin",    "password"),
    ("admin",    "1234"),
    ("admin",    ""),
    ("root",     "root"),
    ("root",     ""),
    ("admin",    "admin123"),
    ("user",     "user"),
    ("guest",    "guest"),
    ("admin",    "12345"),
]

def check_default_creds(ip: str, port: int = 80, https: bool = False) -> dict:
    """Try common default credentials against HTTP Basic Auth. Returns first match or empty."""
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    # First check if auth is even required
    try:
        req = urllib.request.Request(f"{scheme}://{ip}:{port}/",
                                     headers={"User-Agent": "NetScan/2.0"})
        with urllib.request.urlopen(req, timeout=3, context=ctx) as resp:
            if resp.status != 401:
                return {}  # No auth required
    except urllib.error.HTTPError as e:
        if e.code != 401:
            return {}
    except Exception:
        return {}

    import base64
    for user, passwd in DEFAULT_CREDS:
        try:
            creds  = base64.b64encode(f"{user}:{passwd}".encode()).decode()
            req    = urllib.request.Request(
                f"{scheme}://{ip}:{port}/",
                headers={"User-Agent": "NetScan/2.0",
                         "Authorization": f"Basic {creds}"}
            )
            with urllib.request.urlopen(req, timeout=2, context=ctx) as resp:
                if resp.status < 400:
                    return {"user": user, "pass": passwd}
        except Exception:
            continue
    return {}

# ── Wake-on-LAN ───────────────────────────────────────────────────────────────
def wake_on_lan(mac: str) -> bool:
    """Send a WoL magic packet to the broadcast address."""
    try:
        mac_clean = mac.replace(":", "").replace("-", "")
        if len(mac_clean) != 12:
            return False
        mac_bytes = bytes.fromhex(mac_clean)
        magic     = b'\xff' * 6 + mac_bytes * 16
        sock      = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.sendto(magic, ('<broadcast>', 9))
        sock.close()
        return True
    except Exception:
        return False

# ── Traceroute ────────────────────────────────────────────────────────────────
def traceroute(ip: str, max_hops: int = 15) -> list[dict]:
    """
    Run system traceroute and parse output.
    Returns list of {hop, ip, latency_ms}.
    """
    import subprocess, platform
    hops = []
    sys = platform.system().lower()
    try:
        if sys == "windows":
            cmd = ["tracert", "-d", "-h", str(max_hops), ip]
        else:
            cmd = ["traceroute", "-n", "-m", str(max_hops), "-w", "1", ip]

        r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        for line in r.stdout.splitlines():
            # Linux: " 1  192.168.1.1  0.543 ms"
            m = re.match(r'\s*(\d+)\s+([\d.]+|\*)\s+.*?([\d.]+)\s*ms', line)
            if m:
                hops.append({
                    "hop": int(m.group(1)),
                    "ip":  m.group(2),
                    "ms":  float(m.group(3)),
                })
            elif re.match(r'\s*(\d+)\s+\*', line):
                hop_n = int(re.match(r'\s*(\d+)', line).group(1))
                hops.append({"hop": hop_n, "ip": "*", "ms": None})
    except Exception:
        pass
    return hops

# ── Risk scoring ──────────────────────────────────────────────────────────────
RISK_RULES = [
    (23,   3, "Telnet open — unencrypted remote access"),
    (21,   2, "FTP open — unencrypted file transfer"),
    (5900, 2, "VNC open — remote desktop without VPN"),
    (3389, 2, "RDP exposed — Windows remote desktop"),
    (1883, 2, "MQTT open — IoT broker without auth"),
    (445,  1, "SMB open — Windows file sharing"),
    (139,  1, "NetBIOS open"),
    (135,  1, "RPC open"),
    (8883, 1, "MQTT-TLS open"),
    (80,   1, "HTTP (unencrypted web interface)"),
    (8080, 1, "HTTP-Alt open"),
]
RISK_REDUCE = {22, 443, 8443}  # SSH/HTTPS reduce risk

def score_risk(ports: dict, banners: dict = None) -> tuple[int, list[str]]:
    """Returns (score 0-4, list of finding strings)."""
    open_ports = set(int(p) for p in ports.keys())
    score      = 0
    findings   = []
    for port, weight, reason in RISK_RULES:
        if port in open_ports:
            score += weight
            findings.append(reason)
    # Reduce if hardened ports present
    if open_ports & RISK_REDUCE:
        score = max(0, score - 1)
    # Check default creds in banners
    if banners and banners.get("default_creds"):
        score += 2
        findings.append(f"Default credentials work: {banners['default_creds']['user']}/{banners['default_creds']['pass']}")
    return min(score, 4), findings

# ── Full enrichment pipeline ──────────────────────────────────────────────────
def enrich_host(h: dict) -> dict:
    """
    Run all enrichment on a live host dict (in-place, returns same dict).
    Designed to run after basic fingerprint — adds banners, HTTP info,
    SNMP, NetBIOS, CVEs, risk findings.
    """
    ip    = h["ip"]
    ports = {int(k): v for k, v in h.get("ports", {}).items()}

    with ThreadPoolExecutor(max_workers=8) as ex:
        futures = {}

        if 22 in ports:
            futures["banner_ssh"] = ex.submit(grab_ssh_banner, ip)
        if 21 in ports:
            futures["banner_ftp"] = ex.submit(grab_ftp_banner, ip)
        if 25 in ports:
            futures["banner_smtp"] = ex.submit(grab_smtp_banner, ip)
        if 23 in ports:
            futures["banner_telnet"] = ex.submit(grab_telnet_banner, ip)
        if 80 in ports:
            futures["http_80"] = ex.submit(grab_http_info, ip, 80, False)
        if 443 in ports:
            futures["http_443"] = ex.submit(grab_http_info, ip, 443, True)
        if 8080 in ports:
            futures["http_8080"] = ex.submit(grab_http_info, ip, 8080, False)
        futures["snmp"]    = ex.submit(snmp_query, ip)
        futures["netbios"] = ex.submit(netbios_query, ip)
        futures["creds_80"] = ex.submit(check_default_creds, ip, 80, False)

        results = {k: f.result() for k, f in futures.items()}

    h["banner_ssh"]   = results.get("banner_ssh", "")
    h["banner_ftp"]   = results.get("banner_ftp", "")
    h["banner_smtp"]  = results.get("banner_smtp", "")
    h["banner_telnet"]= results.get("banner_telnet", "")

    # HTTP: prefer 443 > 80 > 8080 for title/server
    for key in ("http_443", "http_80", "http_8080"):
        info = results.get(key, {})
        if info and info.get("title"):
            h["http_title"]  = info.get("title", "")
            h["http_server"] = info.get("server", "")
            h["http_url"]    = info.get("url", "")
            break
    else:
        for key in ("http_443", "http_80", "http_8080"):
            info = results.get(key, {})
            if info and info.get("server"):
                h["http_server"] = info.get("server", "")
                h["http_url"]    = info.get("url", "")
                break

    snmp = results.get("snmp", {})
    h["snmp_desc"]   = snmp.get("desc", "")
    h["snmp_uptime"] = snmp.get("uptime", "")

    nb = results.get("netbios", "")
    if nb:
        h["netbios_name"] = nb
        if not h.get("hostname") or h.get("hostname") == "—":
            h["hostname"] = nb

    dc = results.get("creds_80", {})
    h["default_creds"] = dc if dc else None

    # CVE lookup on SSH banner and HTTP server
    h["cves"] = []
    for banner_key in ("banner_ssh", "http_server", "snmp_desc"):
        val = h.get(banner_key, "")
        if val and len(val) > 4:
            cves = lookup_cves(val)
            if cves:
                h["cves"].extend(cves)
                break

    # Recalculate risk with full info
    risk_score, findings = score_risk(h.get("ports", {}), h)
    h["risk"]     = risk_score
    h["findings"] = findings

    return h
