#!/bin/bash
# =============================================================================
#  HTTPS con Let's Encrypt + nginx — Ubuntu Server 22.04
# =============================================================================
set -e

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
ok()   { echo -e "${GREEN}[OK]${NC} $1"; }
warn() { echo -e "${YELLOW}[!!]${NC} $1"; }
err()  { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

# =========================================================
#  EDITA ESTAS VARIABLES ANTES DE EJECUTAR
# =========================================================
DOMAIN="rendiciones.tuempresa.com"
EMAIL="admin@tuempresa.com"
APP_DIR="/opt/viaticos"
APP_PORT="5000"
# =========================================================

[[ $EUID -ne 0 ]] && err "Ejecuta como root: sudo bash setup_https_ubuntu.sh"

echo "============================================================"
echo "  Configuración HTTPS — $DOMAIN"
echo "============================================================"
echo

# ---- 1. Verificar que nginx y certbot estén instalados ----
command -v nginx   >/dev/null 2>&1 || apt-get install -y nginx
command -v certbot >/dev/null 2>&1 || apt-get install -y certbot python3-certbot-nginx
ok "nginx y certbot disponibles."

# ---- 2. Configuración nginx solo HTTP (sin SSL aún) ----
# Certbot necesita que nginx esté activo en el puerto 80 para el challenge ACME.
# Luego certbot modifica este archivo automáticamente para agregar SSL.
echo "[1/4] Configurando nginx (HTTP temporal para obtener certificado)..."
cat > /etc/nginx/sites-available/viaticos <<EOF
# Configuración inicial HTTP — certbot agregará SSL automáticamente

server {
    listen 80;
    listen [::]:80;
    server_name ${DOMAIN};

    # ACME HTTP-01 challenge
    location /.well-known/acme-challenge/ {
        root /var/www/html;
    }

    # Límite de subida de archivos
    client_max_body_size 20M;

    # Archivos estáticos
    location /static/ {
        alias ${APP_DIR}/app/static/;
        expires 7d;
        add_header Cache-Control "public, immutable";
        access_log off;
    }

    # Proxy a la aplicación Flask/Waitress
    location / {
        proxy_pass         http://127.0.0.1:${APP_PORT};
        proxy_set_header   Host \$host;
        proxy_set_header   X-Real-IP \$remote_addr;
        proxy_set_header   X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto \$scheme;
        proxy_read_timeout 120s;
        proxy_connect_timeout 10s;
        proxy_buffering    off;
    }
}
EOF

# Activar sitio y desactivar default
ln -sf /etc/nginx/sites-available/viaticos /etc/nginx/sites-enabled/viaticos
rm -f /etc/nginx/sites-enabled/default

nginx -t || err "Configuración nginx inválida. Revisa el archivo y vuelve a intentar."
systemctl enable nginx
systemctl restart nginx
ok "nginx activo en puerto 80."

# ---- 3. Obtener certificado y configurar HTTPS ----
# certbot --nginx modifica el archivo de configuración automáticamente:
# agrega ssl_certificate, ssl_certificate_key, options-ssl-nginx.conf,
# ssl_dhparam y la redirección HTTP→HTTPS.
echo "[2/4] Solicitando certificado Let's Encrypt para ${DOMAIN}..."
echo "      (El dominio debe apuntar a la IP pública de este servidor)"
echo

certbot --nginx \
    -d "$DOMAIN" \
    --non-interactive \
    --agree-tos \
    --email "$EMAIL" \
    --redirect \
    --hsts \
    --staple-ocsp

ok "Certificado obtenido. nginx recargado con TLS."

# ---- 4. Agregar cabeceras de seguridad extra (certbot no las incluye) ----
echo "[3/4] Agregando cabeceras de seguridad..."
# Insertar cabeceras en el bloque SSL que certbot generó
NGINX_CONF="/etc/nginx/sites-available/viaticos"
if ! grep -q "X-Frame-Options" "$NGINX_CONF"; then
    sed -i '/ssl_certificate /a\
\    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;\
    add_header X-Frame-Options SAMEORIGIN always;\
    add_header X-Content-Type-Options nosniff always;\
    add_header X-XSS-Protection "1; mode=block" always;\
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;' "$NGINX_CONF"
    nginx -t && systemctl reload nginx
    ok "Cabeceras de seguridad agregadas."
else
    ok "Cabeceras de seguridad ya presentes."
fi

# ---- 5. Firewall UFW ----
echo "[4/4] Configurando firewall..."
ufw allow 'Nginx Full'
ufw allow OpenSSH
ufw --force enable
ok "Firewall configurado (puertos 80, 443 y SSH abiertos)."

# ---- Verificar renovación automática ----
certbot renew --dry-run && ok "Renovación automática verificada (systemd timer activo)."

echo
echo "============================================================"
echo -e "  ${GREEN}HTTPS configurado exitosamente!${NC}"
echo "  Accede en: https://${DOMAIN}"
echo
echo "  Certificado: Let's Encrypt (válido 90 días, renovación automática)"
echo "  Ver estado:  systemctl status certbot.timer"
echo "  Ver logs:    sudo journalctl -u viaticos -f"
echo "============================================================"
