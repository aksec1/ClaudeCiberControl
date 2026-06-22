#!/bin/bash
# ClaudeCiberControl - Installation Script
# Installs system dependencies and Python packages

set -e

echo "╔══════════════════════════════════════════════════╗"
echo "║  ClaudeCiberControl - Instalacion de dependencias ║"
echo "╚══════════════════════════════════════════════════╝"

# System packages
echo "[*] Instalando paquetes del sistema..."
if command -v apt-get &>/dev/null; then
    apt-get update -qq
    apt-get install -y nmap python3-pip python3-dev
elif command -v yum &>/dev/null; then
    yum install -y nmap python3 python3-pip
elif command -v brew &>/dev/null; then
    brew install nmap python3
fi

# Python packages
echo "[*] Instalando paquetes Python..."
pip3 install requests beautifulsoup4 jinja2 fpdf2 colorama tabulate dnspython python-whois

# python-nmap manual install (compatible with Python 3.11+)
echo "[*] Instalando python-nmap..."
pip3 download python-nmap -d /tmp/nmap_pkg 2>/dev/null || true
if [ -d /tmp/python-nmap-0.7.1 ]; then
    rm -rf /tmp/python-nmap-0.7.1
fi
cd /tmp && tar xzf /tmp/nmap_pkg/python-nmap-*.tar.gz 2>/dev/null || pip3 install python-nmap

# Try to copy nmap module if pip install failed
PYTHON_SITE=$(python3 -c "import site; print(site.getsitepackages()[0])" 2>/dev/null || echo "/usr/local/lib/python3.x/dist-packages")
if ! python3 -c "import nmap" 2>/dev/null; then
    NMAP_DIR=$(find /tmp -name "nmap" -type d 2>/dev/null | head -1)
    if [ -n "$NMAP_DIR" ]; then
        cp -r "$NMAP_DIR" "$PYTHON_SITE/"
    fi
fi

echo ""
python3 -c "import nmap; print('[✓] python-nmap OK:', nmap.__version__)"
echo ""
echo "[✓] Instalacion completada"
echo "Uso: python3 main.py <target>"
echo "Demo: python3 main.py --demo"
