#!/usr/bin/env bash
# NetScan v2 — setup and launch
set -e
cd "$(dirname "$0")"
echo ""
echo "  ╔══════════════════════════════════════════╗"
echo "  ║         NetScan v2 — Setup & Launch       ║"
echo "  ╚══════════════════════════════════════════╝"
echo ""
echo "  → Checking dependencies..."
python3 -c "import flask" 2>/dev/null || sudo apt install -y python3-flask python3-flask-cors python3-requests
python3 -c "import flask_cors" 2>/dev/null || sudo apt install -y python3-flask-cors
echo "  ✓  Dependencies ready"
echo ""
echo "  → http://127.0.0.1:5000  (loopback only by default)"
echo "    Set NETSCAN_HOST=0.0.0.0 to allow LAN access,"
echo "    and NETSCAN_TOKEN=<secret> to require it on"
echo "    WoL / stop / monitor / rescan / exclude endpoints."
echo "  Press Ctrl+C to stop."
echo ""
sudo python3 server.py
