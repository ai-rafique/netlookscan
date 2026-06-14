#!/usr/bin/env python3
"""
db.py — SQLite persistence layer
Tables: scans, hosts, ports, changes, alerts, cve_cache
"""

import sqlite3, json, os
from datetime import datetime
from pathlib import Path

DB_PATH = Path(__file__).parent / "netscan.db"

# ── Schema ────────────────────────────────────────────────────────────────────
SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS scans (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    subnet      TEXT    NOT NULL,
    started_at  TEXT    NOT NULL,
    finished_at TEXT,
    hosts_found INTEGER DEFAULT 0,
    total_ports INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS hosts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id     INTEGER NOT NULL REFERENCES scans(id),
    ip          TEXT    NOT NULL,
    hostname    TEXT,
    mac         TEXT,
    vendor      TEXT,
    os_guess    TEXT,
    ttl         INTEGER,
    latency     INTEGER,
    device_type TEXT,
    type_key    TEXT,
    label       TEXT,
    risk        INTEGER DEFAULT 0,
    banner_ssh  TEXT,
    banner_http TEXT,
    banner_ftp  TEXT,
    banner_smtp TEXT,
    http_title  TEXT,
    http_server TEXT,
    snmp_desc   TEXT,
    snmp_uptime TEXT,
    netbios_name TEXT,
    first_seen  TEXT,
    last_seen   TEXT
);

CREATE TABLE IF NOT EXISTS ports (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id INTEGER NOT NULL REFERENCES hosts(id),
    port    INTEGER NOT NULL,
    service TEXT
);

CREATE TABLE IF NOT EXISTS known_hosts (
    ip          TEXT PRIMARY KEY,
    mac         TEXT,
    hostname    TEXT,
    vendor      TEXT,
    label       TEXT,
    type_key    TEXT,
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL,
    last_ports  TEXT,   -- JSON array of port numbers
    last_scan_id INTEGER
);

CREATE TABLE IF NOT EXISTS changes (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id     INTEGER NOT NULL,
    ip          TEXT    NOT NULL,
    change_type TEXT    NOT NULL,  -- new_host|lost_host|new_port|closed_port|ip_changed
    detail      TEXT,
    detected_at TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS cve_cache (
    product     TEXT PRIMARY KEY,
    cves        TEXT,   -- JSON
    fetched_at  TEXT
);
"""

def get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_conn() as conn:
        conn.executescript(SCHEMA)

# ── Scan CRUD ─────────────────────────────────────────────────────────────────
def create_scan(subnet: str) -> int:
    with get_conn() as conn:
        cur = conn.execute(
            "INSERT INTO scans (subnet, started_at) VALUES (?,?)",
            (subnet, datetime.now().isoformat())
        )
        return cur.lastrowid

def finish_scan(scan_id: int, hosts_found: int, total_ports: int):
    with get_conn() as conn:
        conn.execute(
            "UPDATE scans SET finished_at=?, hosts_found=?, total_ports=? WHERE id=?",
            (datetime.now().isoformat(), hosts_found, total_ports, scan_id)
        )

def get_scans(limit=50) -> list[dict]:
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM scans ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]

def get_scan_hosts(scan_id: int) -> list[dict]:
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT h.*, GROUP_CONCAT(p.port||':'||p.service) as port_list "
            "FROM hosts h LEFT JOIN ports p ON p.host_id=h.id "
            "WHERE h.scan_id=? GROUP BY h.id ORDER BY h.ip", (scan_id,)
        ).fetchall()
        result = []
        for r in rows:
            d = dict(r)
            d["ports"] = {}
            if d["port_list"]:
                for item in d["port_list"].split(","):
                    parts = item.split(":", 1)
                    if len(parts) == 2:
                        d["ports"][parts[0]] = parts[1]
            del d["port_list"]
            result.append(d)
        return result

# ── Host persistence ──────────────────────────────────────────────────────────
def save_host(scan_id: int, h: dict) -> int:
    now = datetime.now().isoformat()
    ports = h.get("ports", {})
    with get_conn() as conn:
        cur = conn.execute("""
            INSERT INTO hosts
              (scan_id,ip,hostname,mac,vendor,os_guess,ttl,latency,
               device_type,type_key,label,risk,
               banner_ssh,banner_http,banner_ftp,banner_smtp,
               http_title,http_server,snmp_desc,snmp_uptime,
               netbios_name,first_seen,last_seen)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, (
            scan_id, h.get("ip"), h.get("hostname"), h.get("mac"), h.get("vendor"),
            h.get("os") or h.get("os_guess"), h.get("ttlRaw") or h.get("ttl"),
            h.get("latency"), h.get("device_type"), h.get("type"),
            h.get("label"), h.get("risk", 0),
            h.get("banner_ssh"), h.get("banner_http"),
            h.get("banner_ftp"), h.get("banner_smtp"),
            h.get("http_title"), h.get("http_server"),
            h.get("snmp_desc"), h.get("snmp_uptime"),
            h.get("netbios_name"), now, now
        ))
        host_id = cur.lastrowid
        for port, svc in ports.items():
            conn.execute(
                "INSERT INTO ports (host_id,port,service) VALUES (?,?,?)",
                (host_id, int(port), svc)
            )
        return host_id

# ── Known hosts + change detection ───────────────────────────────────────────
def detect_changes(scan_id: int, current_hosts: list[dict]) -> list[dict]:
    """Compare current scan to known_hosts table. Returns list of change dicts."""
    changes = []
    now = datetime.now().isoformat()
    with get_conn() as conn:
        known = {r["ip"]: dict(r) for r in conn.execute("SELECT * FROM known_hosts").fetchall()}
        current_ips = {h["ip"] for h in current_hosts}

        # Lost hosts
        for ip, kh in known.items():
            if ip not in current_ips:
                changes.append({"scan_id": scan_id, "ip": ip,
                    "change_type": "lost_host",
                    "detail": f"Host {ip} ({kh['hostname'] or '?'}) no longer responding",
                    "detected_at": now})

        for h in current_hosts:
            ip = h["ip"]
            curr_ports = set(str(p) for p in h.get("ports", {}).keys())
            if ip not in known:
                changes.append({"scan_id": scan_id, "ip": ip,
                    "change_type": "new_host",
                    "detail": f"New host: {ip} ({h.get('hostname','?')}) [{h.get('label','?')}]",
                    "detected_at": now})
            else:
                prev_ports = set(json.loads(known[ip]["last_ports"] or "[]"))
                new_ports  = curr_ports - prev_ports
                closed     = prev_ports - curr_ports
                for p in new_ports:
                    svc = h.get("ports", {}).get(p, "?")
                    changes.append({"scan_id": scan_id, "ip": ip,
                        "change_type": "new_port",
                        "detail": f"New open port on {ip}: {p}/{svc}",
                        "detected_at": now})
                for p in closed:
                    changes.append({"scan_id": scan_id, "ip": ip,
                        "change_type": "closed_port",
                        "detail": f"Port closed on {ip}: {p}",
                        "detected_at": now})

        # Persist changes
        for c in changes:
            conn.execute(
                "INSERT INTO changes (scan_id,ip,change_type,detail,detected_at) VALUES (?,?,?,?,?)",
                (c["scan_id"], c["ip"], c["change_type"], c["detail"], c["detected_at"])
            )

        # Update known_hosts
        for h in current_hosts:
            ip = h["ip"]
            ports_json = json.dumps(list(h.get("ports", {}).keys()))
            if ip in known:
                conn.execute("""
                    UPDATE known_hosts SET last_seen=?,hostname=?,vendor=?,
                    label=?,type_key=?,last_ports=?,last_scan_id=? WHERE ip=?
                """, (now, h.get("hostname"), h.get("vendor"),
                      h.get("label"), h.get("type"), ports_json, scan_id, ip))
            else:
                conn.execute("""
                    INSERT INTO known_hosts
                      (ip,mac,hostname,vendor,label,type_key,first_seen,last_seen,last_ports,last_scan_id)
                    VALUES (?,?,?,?,?,?,?,?,?,?)
                """, (ip, h.get("mac"), h.get("hostname"), h.get("vendor"),
                      h.get("label"), h.get("type"), now, now, ports_json, scan_id))
    return changes

def get_changes(limit=100) -> list[dict]:
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM changes ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]

def get_known_hosts() -> list[dict]:
    with get_conn() as conn:
        rows = conn.execute("SELECT * FROM known_hosts ORDER BY ip").fetchall()
        return [dict(r) for r in rows]

# ── CVE cache ─────────────────────────────────────────────────────────────────
def get_cve_cache(product: str) -> dict | None:
    with get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM cve_cache WHERE product=?", (product,)
        ).fetchone()
        if row:
            return {"cves": json.loads(row["cves"] or "[]"), "fetched_at": row["fetched_at"]}
    return None

def set_cve_cache(product: str, cves: list):
    with get_conn() as conn:
        conn.execute("""
            INSERT OR REPLACE INTO cve_cache (product,cves,fetched_at)
            VALUES (?,?,?)
        """, (product, json.dumps(cves), datetime.now().isoformat()))

# ── Stats ─────────────────────────────────────────────────────────────────────
def get_stats() -> dict:
    with get_conn() as conn:
        scans      = conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
        known      = conn.execute("SELECT COUNT(*) FROM known_hosts").fetchone()[0]
        changes_n  = conn.execute("SELECT COUNT(*) FROM changes").fetchone()[0]
        last_scan  = conn.execute("SELECT * FROM scans ORDER BY id DESC LIMIT 1").fetchone()
        return {
            "total_scans": scans,
            "known_hosts": known,
            "total_changes": changes_n,
            "last_scan": dict(last_scan) if last_scan else None,
        }
