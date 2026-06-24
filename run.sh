#!/bin/bash
# ClaudeCiberControl - On-Premise Launcher
# Usage:
#   ./run.sh <target> [options]
#   ./run.sh --demo
#   ./run.sh --help

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

MODE="${CCC_MODE:-native}"   # native | docker

show_help() {
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║         ClaudeCiberControl - On-Premise Launcher             ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo ""
    echo "Uso: ./run.sh [TARGET] [OPCIONES]"
    echo ""
    echo "Variables de entorno:"
    echo "  CCC_MODE=native (default) | docker"
    echo ""
    echo "Ejemplos:"
    echo "  ./run.sh 192.168.1.1"
    echo "  ./run.sh example.com --profile full"
    echo "  ./run.sh https://example.com --profile vuln"
    echo "  ./run.sh --demo"
    echo "  ./run.sh --list-profiles"
    echo "  CCC_MODE=docker ./run.sh 192.168.1.1 --profile fast"
    echo ""
    echo "Perfiles disponibles: fast | default | full | vuln | stealth | udp | comprehensive"
}

check_root_or_caps() {
    if [ "$EUID" -ne 0 ]; then
        if ! command -v setcap &>/dev/null || ! getcap "$(which nmap)" 2>/dev/null | grep -q "cap_net_raw"; then
            echo "[!] Advertencia: nmap requiere privilegios para SYN scan y deteccion de OS."
            echo "    Ejecuta con sudo, o asigna capabilities:"
            echo "    sudo setcap cap_net_raw,cap_net_admin+eip \$(which nmap)"
            echo ""
        fi
    fi
}

run_native() {
    check_root_or_caps

    if ! command -v python3 &>/dev/null; then
        echo "[ERROR] Python3 no encontrado. Ejecuta: ./install.sh"
        exit 1
    fi

    if ! python3 -c "import nmap" 2>/dev/null; then
        echo "[ERROR] python-nmap no instalado. Ejecuta: ./install.sh"
        exit 1
    fi

    mkdir -p output/reports output/logs

    python3 main.py "$@"
}

run_docker() {
    if ! command -v docker &>/dev/null; then
        echo "[ERROR] Docker no encontrado."
        exit 1
    fi

    # Build image if not exists
    if ! docker image inspect cibercontrol:latest &>/dev/null; then
        echo "[*] Construyendo imagen Docker..."
        docker compose build
    fi

    mkdir -p output/reports output/logs

    docker compose run --rm \
        --cap-add NET_ADMIN \
        --cap-add NET_RAW \
        -v "$(pwd)/output:/app/output" \
        cibercontrol "$@"
}

if [ $# -eq 0 ] || [ "$1" = "--help" ] || [ "$1" = "-h" ]; then
    show_help
    echo ""
    python3 main.py --help 2>/dev/null || true
    exit 0
fi

case "$MODE" in
    docker)
        run_docker "$@"
        ;;
    native|*)
        run_native "$@"
        ;;
esac
