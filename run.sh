#!/bin/bash
# ClaudeCiberControl - On-Premise Launcher

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

MODE="${CCC_MODE:-native}"

if [ $# -eq 0 ] || [ "$1" = "--help" ] || [ "$1" = "-h" ]; then
    echo "ClaudeCiberControl - On-Premise Launcher"
    echo ""
    echo "Uso: ./run.sh [TARGET] [OPCIONES]"
    echo "Ejemplos:"
    echo "  ./run.sh 192.168.1.1"
    echo "  ./run.sh example.com --profile full"
    echo "  ./run.sh https://example.com --profile vuln"
    echo "  ./run.sh --demo"
    echo "  CCC_MODE=docker ./run.sh 192.168.1.1"
    echo ""
    echo "Perfiles: fast | default | full | vuln | stealth | udp | comprehensive"
    exit 0
fi

if [ "$MODE" = "docker" ]; then
    if ! command -v docker &>/dev/null; then
        echo "[ERROR] Docker no encontrado."; exit 1
    fi
    if ! docker image inspect cibercontrol:latest &>/dev/null; then
        echo "[*] Construyendo imagen Docker..."
        docker compose build
    fi
    mkdir -p output/reports output/logs
    docker compose run --rm --cap-add NET_ADMIN --cap-add NET_RAW \
        -v "$(pwd)/output:/app/output" cibercontrol "$@"
else
    if [ -f "$SCRIPT_DIR/.venv/bin/python3" ]; then
        PYTHON="$SCRIPT_DIR/.venv/bin/python3"
    else
        PYTHON=python3
    fi
    if [ "$EUID" -ne 0 ]; then
        if ! getcap "$(which nmap)" 2>/dev/null | grep -q "cap_net_raw"; then
            echo "[!] nmap sin privilegios - SYN scan puede fallar. Ejecuta: sudo ./install.sh"
        fi
    fi
    mkdir -p output/reports output/logs
    "$PYTHON" main.py "$@"
fi
