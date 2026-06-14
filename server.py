#!/usr/bin/env python3
"""
server.py — NetScan v2 Flask backend
All endpoints served from http://localhost:5000

SSE scan stream   GET  /api/scan?subnet=192.168.1&end=255
Status            GET  /api/status
Stop scan         POST /api/stop
Last results      GET  /api/last
Scan history      GET  /api/history
Hosts in scan     GET  /api/history/<scan_id>/hosts
Known hosts       GET  /api/known
Change log        GET  /api/changes
Stats             GET  /api/stats
Traceroute        GET  /api/traceroute?ip=x.x.x.x
Wake on LAN       POST /api/wol  {"mac": "xx:xx:xx:xx:xx:xx"}
CVE lookup        GET  /api/cve?q=OpenSSH+9.2
Webhook config    GET/POST /api/webhook
Monitoring        GET  /api/monitor/status
                  POST /api/monitor/start  {"interval": 300}
                  POST /api/monitor/stop
"""

import json, os, threading, time, platform, subprocess, re
from datetime import datetime
from functools import wraps
from pathlib import Path

from flask import Flask, Response, request, jsonify, send_from_directory
from flask_cors import CORS

from scanner_core import ping, fingerprint, COMMON_PORTS
import db
import enrichment

# ── Configuration (env-overridable) ──────────────────────────────────────────
# Previously bound 0.0.0.0 with wide-open CORS — a Flask process run as
# root, with /api/wol, /api/deepscan, /api/stop and /api/monitor/* reachable
# by anyone on the LAN with no auth. Default is now loopback-only.
#   NETSCAN_HOST=0.0.0.0     opt in to LAN access
#   NETSCAN_PORT=5000        change the port
#   NETSCAN_TOKEN=...        require X-NetScan-Token on mutating endpoints
#   NETSCAN_ORIGINS=a,b      override allowed CORS origins
HOST      = os.environ.get("NETSCAN_HOST", "127.0.0.1")
PORT      = int(os.environ.get("NETSCAN_PORT", "5000"))
API_TOKEN = os.environ.get("NETSCAN_TOKEN", "").strip()
ALLOWED_ORIGINS = os.environ.get(
    "NETSCAN_ORIGINS", f"http://127.0.0.1:{PORT},http://localhost:{PORT}"
).split(",")

# ── App setup ─────────────────────────────────────────────────────────────────
app = Flask(__name__, static_folder=".")
CORS(app, origins=ALLOWED_ORIGINS)
db.init_db()

HERE = Path(__file__).parent

def require_token(fn):
    """
    Guards mutating endpoints (WoL, stop, monitor, rescan, exclude).
    No-op unless NETSCAN_TOKEN is set, so the default loopback-only
    setup behaves exactly as before.
    """
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if API_TOKEN and request.headers.get("X-NetScan-Token", "") != API_TOKEN:
            return jsonify({"error": "unauthorized"}), 401
        return fn(*args, **kwargs)
    return wrapper

_IP_RE = re.compile(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$")

def _valid_ip(ip: str) -> bool:
    m = _IP_RE.match(ip)
    return bool(m) and all(0 <= int(o) <= 255 for o in m.groups())

# ── Global state ──────────────────────────────────────────────────────────────
_state = {
    "scanning":    False,
    "scan_id":     None,
    "hosts_found": 0,
    "scanned":     0,
    "total":       0,
    "subnet":      "",
}
_stop_event   = threading.Event()
_last_results: list[dict] = []
_monitor_thread = None
_monitor_stop   = threading.Event()
_webhook_url    = ""

# ── UI ────────────────────────────────────────────────────────────────────────
@app.route("/")
def index():
    return send_from_directory(str(HERE), "netscanner.html")

# ── Status ────────────────────────────────────────────────────────────────────
@app.route("/api/status")
def status():
    return jsonify({**_state, "webhook": bool(_webhook_url)})

@app.route("/api/stats")
def stats():
    return jsonify(db.get_stats())

# ── Stop ──────────────────────────────────────────────────────────────────────
@app.route("/api/stop", methods=["POST"])
@require_token
def stop():
    _stop_event.set()
    return jsonify({"ok": True})

# ── Last scan results ─────────────────────────────────────────────────────────
@app.route("/api/last")
def last():
    return jsonify(_last_results)

# ── History ───────────────────────────────────────────────────────────────────
@app.route("/api/history")
def history():
    return jsonify(db.get_scans())

@app.route("/api/history/<int:scan_id>/hosts")
def history_hosts(scan_id):
    hosts = db.get_scan_hosts(scan_id)
    return jsonify(hosts)

# ── Known hosts ───────────────────────────────────────────────────────────────
@app.route("/api/known")
def known():
    return jsonify(db.get_known_hosts())

# ── Change log ────────────────────────────────────────────────────────────────
@app.route("/api/changes")
def changes():
    return jsonify(db.get_changes())

# ── Excluded / muted hosts ────────────────────────────────────────────────────
@app.route("/api/excluded")
def excluded_list():
    return jsonify(sorted(db.get_excluded_ips()))

@app.route("/api/exclude", methods=["POST"])
@require_token
def exclude_host():
    data = request.get_json() or {}
    ip = data.get("ip", "").strip()
    if not _valid_ip(ip):
        return jsonify({"error": "invalid ip"}), 400
    excluded = bool(data.get("excluded", True))
    db.set_excluded(ip, excluded)
    return jsonify({"ok": True, "ip": ip, "excluded": excluded})

# ── Single-host rescan ────────────────────────────────────────────────────────
@app.route("/api/rescan")
@require_token
def rescan():
    """Re-fingerprint a single host without re-running the whole subnet sweep."""
    global _last_results
    ip = request.args.get("ip", "").strip()
    if not _valid_ip(ip):
        return jsonify({"error": "invalid ip"}), 400
    deep = request.args.get("deep", "0") == "1"

    res = ping(ip)
    if not res["alive"]:
        return jsonify({"error": "unreachable", "ip": ip})

    lat = _measure_latency(ip)
    fp  = fingerprint(ip, res["ttl"])
    row = _enrich_for_ui(fp, lat)
    if deep:
        row = enrichment.enrich_host(row)

    db.touch_known_host(ip, row)

    for i, h in enumerate(_last_results):
        if h["ip"] == ip:
            _last_results[i] = row
            break
    else:
        _last_results.append(row)

    return jsonify(row)

# ── Traceroute ────────────────────────────────────────────────────────────────
@app.route("/api/traceroute")
def traceroute():
    ip = request.args.get("ip", "").strip()
    if not ip:
        return jsonify({"error": "ip required"}), 400
    hops = enrichment.traceroute(ip)
    return jsonify({"ip": ip, "hops": hops})

# ── Wake on LAN ───────────────────────────────────────────────────────────────
@app.route("/api/wol", methods=["POST"])
@require_token
def wol():
    data = request.get_json() or {}
    mac  = data.get("mac", "")
    ok   = enrichment.wake_on_lan(mac)
    return jsonify({"ok": ok, "mac": mac})

# ── CVE lookup ────────────────────────────────────────────────────────────────
@app.route("/api/cve")
def cve():
    q    = request.args.get("q", "").strip()
    cves = enrichment.lookup_cves(q)
    return jsonify({"query": q, "cves": cves})

# ── Webhook config ────────────────────────────────────────────────────────────
@app.route("/api/webhook", methods=["GET", "POST"])
def webhook():
    global _webhook_url
    if request.method == "POST":
        data = request.get_json() or {}
        _webhook_url = data.get("url", "").strip()
        return jsonify({"ok": True, "url": _webhook_url})
    return jsonify({"url": _webhook_url})

# ── Monitoring ────────────────────────────────────────────────────────────────
@app.route("/api/monitor/status")
def monitor_status():
    return jsonify({
        "running": _monitor_thread is not None and _monitor_thread.is_alive(),
    })

@app.route("/api/monitor/start", methods=["POST"])
@require_token
def monitor_start():
    global _monitor_thread
    data     = request.get_json() or {}
    interval = int(data.get("interval", 300))
    subnet   = data.get("subnet", "192.168.1")
    _monitor_stop.clear()

    def monitor_loop():
        while not _monitor_stop.is_set():
            _run_scan_blocking(subnet, 255)
            _monitor_stop.wait(interval)

    _monitor_thread = threading.Thread(target=monitor_loop, daemon=True)
    _monitor_thread.start()
    return jsonify({"ok": True, "interval": interval})

@app.route("/api/monitor/stop", methods=["POST"])
@require_token
def monitor_stop_route():
    _monitor_stop.set()
    return jsonify({"ok": True})

# ── Deep port scan ────────────────────────────────────────────────────────────
@app.route("/api/deepscan")
def deep_scan():
    ip      = request.args.get("ip", "").strip()
    port_min = int(request.args.get("min", 1))
    port_max = int(request.args.get("max", 10000))
    if not ip:
        return jsonify({"error": "ip required"}), 400

    def generate():
        yield f"data: {json.dumps({'status':'start','ip':ip,'range':[port_min,port_max]})}\n\n"
        import socket
        from concurrent.futures import ThreadPoolExecutor, as_completed
        open_ports = {}
        all_ports  = list(range(port_min, port_max + 1))
        scanned    = 0

        def probe(port):
            try:
                with socket.create_connection((ip, port), timeout=0.4):
                    return port
            except Exception:
                return None

        with ThreadPoolExecutor(max_workers=200) as ex:
            futures = {ex.submit(probe, p): p for p in all_ports}
            for fut in as_completed(futures):
                scanned += 1
                port = fut.result()
                if port:
                    svc = COMMON_PORTS.get(port, "unknown")
                    open_ports[port] = svc
                    yield f"data: {json.dumps({'status':'open','port':port,'service':svc})}\n\n"
                if scanned % 500 == 0:
                    pct = round(scanned / len(all_ports) * 100)
                    yield f"data: {json.dumps({'status':'progress','pct':pct,'scanned':scanned})}\n\n"

        yield f"data: {json.dumps({'status':'done','open_ports':open_ports,'total_scanned':scanned})}\n\n"

    return Response(generate(), mimetype="text/event-stream",
                    headers={"Cache-Control":"no-cache","X-Accel-Buffering":"no"})

# ── Main scan SSE stream ──────────────────────────────────────────────────────
@app.route("/api/scan")
def scan_stream():
    subnet = request.args.get("subnet", "192.168.1").strip()
    try:
        end = max(1, min(int(request.args.get("end", 255)), 255))
    except ValueError:
        end = 255
    deep = request.args.get("deep", "0") == "1"  # enrich with banners/CVEs

    def generate():
        global _last_results
        if _state["scanning"]:
            yield sse("error", {"msg": "Scan already running"})
            return

        _state.update({"scanning": True, "hosts_found": 0,
                        "scanned": 0, "total": end+1, "subnet": subnet})
        _stop_event.clear()
        _last_results = []

        scan_id = db.create_scan(subnet)
        _state["scan_id"] = scan_id
        ips = [f"{subnet}.{i}" for i in range(0, end + 1)]

        # Everything below runs inside try/finally: if the client
        # disconnects mid-scan, Flask raises GeneratorExit at whichever
        # `yield` is in flight. Without this, _state["scanning"] stayed
        # True forever and no new scan could start until the process
        # was restarted.
        try:
            yield sse("start", {"subnet": subnet, "total": len(ips),
                                 "scan_id": scan_id, "ts": now()})

            # ── Phase 1: parallel ping ───────────────────────────────────────
            from concurrent.futures import ThreadPoolExecutor, as_completed
            alive   = []
            scanned = 0

            with ThreadPoolExecutor(max_workers=60) as ex:
                futures = {ex.submit(ping, ip): ip for ip in ips}
                for fut in as_completed(futures):
                    if _stop_event.is_set():
                        break
                    res = fut.result()
                    scanned += 1
                    _state["scanned"] = scanned
                    yield sse("ping", {
                        "ip":      res["ip"],
                        "alive":   res["alive"],
                        "ttl":     res["ttl"],
                        "scanned": scanned,
                        "total":   len(ips),
                    })
                    if res["alive"]:
                        alive.append(res)

            if _stop_event.is_set():
                yield sse("stopped", {"msg": "Scan stopped"})
                return

            alive.sort(key=lambda x: int(x["ip"].split(".")[-1]))
            yield sse("phase2", {"count": len(alive), "deep": deep})

            # ── Phase 2: fingerprint + optional deep enrichment ──────────────
            results = []
            for i, host in enumerate(alive, 1):
                if _stop_event.is_set():
                    break
                ip, ttl = host["ip"], host["ttl"]
                lat = _measure_latency(ip)
                fp  = fingerprint(ip, ttl)
                row = _enrich_for_ui(fp, lat)

                if deep:
                    yield sse("enriching", {"ip": ip, "step": i, "total": len(alive)})
                    row = enrichment.enrich_host(row)

                results.append(row)
                _last_results.append(row)
                _state["hosts_found"] = len(results)

                # Persist to DB
                db.save_host(scan_id, row)

                yield sse("host", row)

            # ── Change detection ──────────────────────────────────────────────
            changes = db.detect_changes(scan_id, results)
            if changes:
                yield sse("changes", {"changes": changes})
                _fire_webhook(changes, subnet)

            total_ports = sum(len(r.get("ports", {})) for r in results)
            db.finish_scan(scan_id, len(results), total_ports)

            yield sse("done", {
                "hosts":       len(results),
                "total_ports": total_ports,
                "changes":     len(changes),
                "scan_id":     scan_id,
                "ts":          now(),
            })
        finally:
            _state["scanning"] = False

    return Response(generate(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache",
                             "X-Accel-Buffering": "no"})

# ── Helpers ───────────────────────────────────────────────────────────────────
def sse(event: str, data: dict) -> str:
    return f"event: {event}\ndata: {json.dumps(data)}\n\n"

def now() -> str:
    return datetime.now().isoformat()

def _run_scan_blocking(subnet: str, end: int):
    """Non-streaming scan for the monitor loop."""
    from concurrent.futures import ThreadPoolExecutor, as_completed
    ips   = [f"{subnet}.{i}" for i in range(0, end + 1)]
    alive = []
    with ThreadPoolExecutor(max_workers=60) as ex:
        futures = {ex.submit(ping, ip): ip for ip in ips}
        for fut in as_completed(futures):
            res = fut.result()
            if res["alive"]:
                alive.append(res)
    results = []
    for host in alive:
        fp  = fingerprint(host["ip"], host["ttl"])
        row = _enrich_for_ui(fp, _measure_latency(host["ip"]))
        results.append(row)
    scan_id = db.create_scan(subnet)
    for r in results:
        db.save_host(scan_id, r)
    changes = db.detect_changes(scan_id, results)
    db.finish_scan(scan_id, len(results), sum(len(r.get("ports",{})) for r in results))
    global _last_results
    _last_results = results
    if changes:
        _fire_webhook(changes, subnet)

def _measure_latency(ip: str) -> int:
    try:
        sys = platform.system().lower()
        cmd = ["ping","-n","1","-w","1000",ip] if sys=="windows" else ["ping","-c","1","-W","1",ip]
        r   = subprocess.run(cmd, capture_output=True, text=True, timeout=2)
        m   = re.search(r"time[<=]([\d.]+)\s*ms", r.stdout, re.I)
        if m:
            return max(1, round(float(m.group(1))))
    except Exception:
        pass
    return 0

def _enrich_for_ui(fp: dict, latency: int) -> dict:
    """Map raw fingerprint to UI-ready dict."""
    ports_str = {str(k): v for k, v in fp["open_ports"].items()}
    type_key, label, ico, bdg = _device_meta(fp["device_type"])
    bg_map = {
        "router":  "rgba(0,229,160,.15)",  "server": "rgba(74,154,255,.15)",
        "windows": "rgba(167,139,250,.15)","macos":  "rgba(167,139,250,.15)",
        "printer": "rgba(240,165,0,.15)",  "nas":    "rgba(0,229,160,.15)",
        "iot":     "rgba(240,165,0,.15)",  "mobile": "rgba(0,229,160,.12)",
        "vm":      "rgba(74,154,255,.1)",
    }
    risk_score, findings = enrichment.score_risk(fp["open_ports"])
    return {
        "ip":          fp["ip"],
        "hostname":    fp["hostname"],
        "os":          fp["os_guess"],
        "ttlRaw":      fp["ttl"] or 0,
        "mac":         fp["mac"],
        "vendor":      fp["vendor"],
        "ports":       ports_str,
        "device_type": fp["device_type"],
        "type":        type_key,
        "label":       label,
        "ico":         ico,
        "bdg":         bdg,
        "bdgbg":       bg_map.get(type_key, "rgba(74,154,255,.1)"),
        "bg":          bg_map.get(type_key, "rgba(74,154,255,.1)"),
        "risk":        risk_score,
        "findings":    findings,
        "latency":     latency,
        "firstSeen":   datetime.now().strftime("%H:%M:%S"),
        "cves":        [],
        "banner_ssh":  "", "banner_http": "", "banner_ftp": "",
        "http_title":  "", "http_server": "",
        "snmp_desc":   "", "snmp_uptime": "",
        "netbios_name":"",
        "default_creds": None,
    }

def _device_meta(device_type: str) -> tuple:
    dt = device_type.lower()
    if "router" in dt or "network" in dt or "cisco" in dt or "unifi" in dt:
        return "router",  "Router / AP",    "🌐", "#00e5a0"
    if "printer" in dt:
        return "printer", "Printer",         "🖨",  "#f0a500"
    if "nas" in dt or "storage" in dt:
        return "nas",     "NAS / Storage",   "💾", "#00e5a0"
    if "windows" in dt:
        return "windows", "Windows",         "💻", "#a78bfa"
    if "macos" in dt or "apple" in dt:
        return "macos",   "macOS",           "🍎", "#a78bfa"
    if "iot" in dt or "smart" in dt:
        return "iot",     "IoT / Smart",     "💡", "#f0a500"
    if "mobile" in dt:
        return "mobile",  "Mobile",          "📱", "#00e5a0"
    if "virtual" in dt or "vm" in dt:
        return "vm",      "Virtual Machine", "🔲", "#4a9eff"
    if "raspberry" in dt:
        return "server",  "Raspberry Pi",    "🍓", "#ff4d6a"
    return "server", "Linux Server", "🖥", "#4a9eff"

def _fire_webhook(changes: list[dict], subnet: str):
    if not _webhook_url:
        return
    import urllib.request, urllib.error
    try:
        payload = json.dumps({
            "event":   "changes_detected",
            "subnet":  subnet,
            "changes": changes,
            "ts":      now(),
        }).encode()
        req = urllib.request.Request(
            _webhook_url, data=payload,
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        urllib.request.urlopen(req, timeout=5)
    except Exception as e:
        print(f"  Webhook error: {e}")

# ── Entry ─────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    token_note = "required (X-NetScan-Token header)" if API_TOKEN else "off — set NETSCAN_TOKEN to enable"
    lan_note   = "" if HOST == "127.0.0.1" else "  (reachable from your LAN)"
    print(f"""
  ╔════════════════════════════════════════════╗
  ║  NetScan v2  →  http://{HOST}:{PORT}
  ╠════════════════════════════════════════════╣
  ║  DB        : netscan.db
  ║  Bind      : {HOST}:{PORT}{lan_note}
  ║  API token : {token_note}
  ║  Deep scan : ?deep=1 on /api/scan
  ║  Rescan    : GET  /api/rescan?ip=x.x.x.x
  ║  Exclude   : POST /api/exclude {{"ip":..,"excluded":true}}
  ║  Monitor   : POST /api/monitor/start
  ╚════════════════════════════════════════════╝
  Set NETSCAN_HOST=0.0.0.0 to allow LAN access.
""")
    app.run(host=HOST, port=PORT, debug=False, threaded=True)
