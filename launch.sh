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
echo "  → http://localhost:5000"
echo "  Press Ctrl+C to stop."
echo ""
sudo python3 server.py
