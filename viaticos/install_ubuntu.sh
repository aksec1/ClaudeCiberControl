#!/bin/bash
# =============================================================================
#  Instalador — Sistema de Rendición de Viáticos
#  Ubuntu Server 22.04 LTS
# =============================================================================
set -e

# ---- Colores ----
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
ok()   { echo -e "${GREEN}[OK]${NC} $1"; }
warn() { echo -e "${YELLOW}[!!]${NC} $1"; }
err()  { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

# ---- Variables (editar antes de ejecutar) ----
APP_DIR="/opt/viaticos"
APP_USER="viaticos"
PYTHON="python3"

echo "============================================================"
echo "  Instalación — Sistema de Rendición de Viáticos"
echo "  Ubuntu Server 22.04"
echo "============================================================"
echo

# ---- Verificar root ----
[[ $EUID -ne 0 ]] && err "Ejecuta este script como root: sudo bash install_ubuntu.sh"

# ---- 1. Dependencias del sistema ----
echo "[1/6] Instalando dependencias del sistema..."
apt-get update -qq
apt-get install -y -qq \
    python3 python3-pip python3-venv \
    nginx certbot python3-certbot-nginx \
    git curl ufw
ok "Dependencias instaladas."

# ---- 2. Crear usuario y directorio ----
echo "[2/6] Configurando usuario y directorio de la aplicación..."
if ! id "$APP_USER" &>/dev/null; then
    useradd --system --no-create-home --shell /bin/false "$APP_USER"
    ok "Usuario '$APP_USER' creado."
fi

# Copiar archivos de la app al directorio de instalación
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ "$SCRIPT_DIR" != "$APP_DIR" ]]; then
    mkdir -p "$APP_DIR"
    cp -r "$SCRIPT_DIR"/. "$APP_DIR/"
fi
chown -R "$APP_USER:$APP_USER" "$APP_DIR"
ok "Archivos copiados en $APP_DIR."

# ---- 3. Entorno virtual Python ----
echo "[3/6] Creando entorno virtual Python..."
# Crear venv como root y luego cambiar ownership (evita warning de pip cache)
"$PYTHON" -m venv "$APP_DIR/venv"
chown -R "$APP_USER:$APP_USER" "$APP_DIR/venv"
# Instalar con HOME explícito para que pip use caché dentro de APP_DIR
sudo -u "$APP_USER" HOME="$APP_DIR" "$APP_DIR/venv/bin/pip" install --upgrade pip -q
sudo -u "$APP_USER" HOME="$APP_DIR" "$APP_DIR/venv/bin/pip" install -r "$APP_DIR/requirements.txt" -q
ok "Dependencias Python instaladas."

# ---- 4. Configuración .env ----
echo "[4/6] Configurando variables de entorno..."
if [[ ! -f "$APP_DIR/.env" ]]; then
    cp "$APP_DIR/.env.example" "$APP_DIR/.env"
    chmod 640 "$APP_DIR/.env"
    chown "$APP_USER:$APP_USER" "$APP_DIR/.env"
    warn "Archivo .env creado. Edítalo antes de iniciar: sudo nano $APP_DIR/.env"
else
    ok ".env ya existe, no se sobreescribe."
fi

# ---- 5. Inicializar base de datos ----
echo "[5/6] Inicializando base de datos..."
# Ejecutar desde APP_DIR para que las rutas relativas residuales resuelvan bien
sudo -u "$APP_USER" HOME="$APP_DIR" \
    bash -c "cd '$APP_DIR' && '$APP_DIR/venv/bin/python' '$APP_DIR/init_db.py'"
ok "Base de datos inicializada."

# ---- 6. Instalar servicio systemd ----
echo "[6/6] Instalando servicio systemd..."
cat > /etc/systemd/system/viaticos.service <<EOF
[Unit]
Description=Sistema Rendición de Viáticos
After=network.target

[Service]
Type=simple
User=${APP_USER}
Group=${APP_USER}
WorkingDirectory=${APP_DIR}
EnvironmentFile=${APP_DIR}/.env
ExecStart=${APP_DIR}/venv/bin/python ${APP_DIR}/run.py
Restart=on-failure
RestartSec=5s
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable viaticos
ok "Servicio systemd instalado y habilitado."

echo
echo "============================================================"
echo -e "  ${GREEN}Instalación completada.${NC}"
echo "============================================================"
echo
echo "  Próximos pasos:"
echo
echo "  1. Editar configuración:"
echo "     sudo nano $APP_DIR/.env"
echo
echo "  2. Iniciar la aplicación:"
echo "     sudo systemctl start viaticos"
echo
echo "  3. Configurar HTTPS (requiere dominio):"
echo "     sudo bash $APP_DIR/nginx/setup_https_ubuntu.sh"
echo
echo "  4. Ver logs:"
echo "     sudo journalctl -u viaticos -f"
echo
echo "  Usuario admin por defecto:"
echo "    Email:      admin@empresa.com"
echo "    Contraseña: Admin1234!"
echo "  CAMBIA LA CONTRASEÑA en el primer ingreso."
echo "============================================================"
