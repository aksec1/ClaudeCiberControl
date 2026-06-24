#!/bin/bash
# ClaudeCiberControl - Installation Script (On-Premise / VM)
# Tested: Ubuntu 20.04/22.04, Debian 11/12, RHEL/Rocky 8/9

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║    ClaudeCiberControl - Instalacion On-Premise               ║"
echo "╚══════════════════════════════════════════════════════════════╝"

# ── Root check ────────────────────────────────────────────────────────────────
if [ "$EUID" -ne 0 ]; then
    echo "[!] Se recomienda ejecutar como root para instalar paquetes del sistema."
    echo "    Continuando como usuario normal (solo dependencias Python)..."
    SKIP_SYS=1
else
    SKIP_SYS=0
fi

# ── System packages ───────────────────────────────────────────────────────────
if [ "$SKIP_SYS" -eq 0 ]; then
    echo ""
    echo "[*] Instalando paquetes del sistema..."
    if command -v apt-get &>/dev/null; then
        apt-get update -qq
        apt-get install -y --no-install-recommends \
            nmap python3 python3-pip python3-dev python3-venv \
            curl wget ca-certificates libssl-dev
    elif command -v dnf &>/dev/null; then
        dnf install -y nmap python3 python3-pip python3-devel
    elif command -v yum &>/dev/null; then
        yum install -y nmap python3 python3-pip python3-devel
    elif command -v brew &>/dev/null; then
        brew install nmap python3
    else
        echo "[!] Gestor de paquetes no reconocido. Instala nmap y python3 manualmente."
    fi

    # Grant nmap raw socket capability so non-root users can run SYN scans
    if command -v setcap &>/dev/null && command -v nmap &>/dev/null; then
        setcap cap_net_raw,cap_net_admin+eip "$(which nmap)" 2>/dev/null || true
        echo "[✓] nmap capabilities configuradas (SYN scan sin root)"
    fi
fi

# ── Python virtual environment ────────────────────────────────────────────────
VENV_DIR="$SCRIPT_DIR/.venv"

echo ""
echo "[*] Creando entorno virtual Python en $VENV_DIR ..."
python3 -m venv "$VENV_DIR"
source "$VENV_DIR/bin/activate"

pip install --upgrade pip --quiet

# ── Python packages ───────────────────────────────────────────────────────────
echo "[*] Instalando dependencias Python..."
pip install --no-cache-dir -r "$SCRIPT_DIR/requirements.txt" --quiet

# ── python-nmap (handle wheel build failures on Python 3.11+) ────────────────
echo "[*] Verificando python-nmap..."
if ! python3 -c "import nmap" 2>/dev/null; then
    echo "[*] Instalando python-nmap manualmente..."
    TMPDIR=$(mktemp -d)
    pip download python-nmap -d "$TMPDIR" --quiet 2>/dev/null || true
    TARBALL=$(find "$TMPDIR" -name "python-nmap-*.tar.gz" | head -1)
    if [ -n "$TARBALL" ]; then
        tar xzf "$TARBALL" -C "$TMPDIR"
        NMAP_MODULE=$(find "$TMPDIR" -name "nmap" -type d | head -1)
        if [ -n "$NMAP_MODULE" ]; then
            SITE_PKG=$(python3 -c "import site; print(site.getsitepackages()[0])")
            cp -r "$NMAP_MODULE" "$SITE_PKG/"
            echo "[✓] python-nmap copiado a $SITE_PKG"
        fi
    fi
    rm -rf "$TMPDIR"
fi

# ── Verification ──────────────────────────────────────────────────────────────
echo ""
echo "[*] Verificando instalacion..."
python3 -c "import nmap; print('[✓] python-nmap:', nmap.__version__)"
python3 -c "import requests; print('[✓] requests:', requests.__version__)"
python3 -c "import bs4; print('[✓] beautifulsoup4:', bs4.__version__)"
python3 -c "import jinja2; print('[✓] jinja2:', jinja2.__version__)"
python3 -c "import fpdf; print('[✓] fpdf2 OK')"
nmap --version 2>/dev/null | head -1 && echo "[✓] nmap sistema OK" || echo "[!] nmap no encontrado en PATH"

# ── Output directories ────────────────────────────────────────────────────────
mkdir -p "$SCRIPT_DIR/output/reports" "$SCRIPT_DIR/output/logs"

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  [✓] Instalacion completada                                  ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
echo "Uso:"
echo "  source .venv/bin/activate"
echo "  python3 main.py <target>"
echo "  python3 main.py --demo"
echo "  python3 main.py 192.168.1.1 --profile full"
echo ""
echo "  O usando el launcher:"
echo "  ./run.sh <target> [--profile <perfil>]"
echo "  ./run.sh --demo"
echo ""
echo "  Docker (opcional):"
echo "  docker compose build"
echo "  docker compose run cibercontrol <target>"
