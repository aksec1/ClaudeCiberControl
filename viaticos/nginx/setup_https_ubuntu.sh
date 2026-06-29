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

# ---- 2. Configuración nginx (HTTP primero para el challenge ACME) ----
echo "[1/4] Configurando nginx..."
cat > /etc/nginx/sites-available/viaticos <<EOF
# Configuración generada automáticamente — Sistema Rendición de Viáticos

# Redirect HTTP → HTTPS
server {
    listen 80;
    listen [::]:80;
    server_name ${DOMAIN};

    # ACME HTTP-01 challenge (Let's Encrypt)
    location /.well-known/acme-challenge/ {
        root /var/www/html;
    }

    location / {
        return 301 https://\$host\$request_uri;
    }
}

# HTTPS
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name ${DOMAIN};

    # Certificados (Certbot los gestiona automáticamente)
    ssl_certificate     /etc/letsencrypt/live/${DOMAIN}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/${DOMAIN}/privkey.pem;
    include             /etc/letsencrypt/options-ssl-nginx.conf;
    ssl_dhparam         /etc/letsencrypt/ssl-dhparams.pem;

    # Cabeceras de seguridad
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Frame-Options SAMEORIGIN always;
    add_header X-Content-Type-Options nosniff always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;

    # Límite de subida de archivos
    client_max_body_size 20M;

    # Archivos estáticos servidos directamente por nginx
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
        proxy_set_header   X-Forwarded-Proto https;
        proxy_read_timeout 120s;
        proxy_connect_timeout 10s;
        proxy_buffering    off;
    }
}
EOF

# Activar sitio y desactivar default
ln -sf /etc/nginx/sites-available/viaticos /etc/nginx/sites-enabled/viaticos
rm -f /etc/nginx/sites-enabled/default

nginx -t && ok "Configuración nginx válida."
systemctl reload nginx

# ---- 3. Obtener certificado Let's Encrypt ----
echo "[2/4] Solicitando certificado Let's Encrypt para ${DOMAIN}..."
echo "      (El dominio debe apuntar a la IP pública de este servidor)"
echo

certbot --nginx \
    -d "$DOMAIN" \
    --non-interactive \
    --agree-tos \
    --email "$EMAIL" \
    --redirect

ok "Certificado obtenido y nginx recargado con TLS."

# ---- 4. Firewall UFW ----
echo "[3/4] Configurando firewall..."
ufw allow 'Nginx Full'   # 80 + 443
ufw allow OpenSSH        # conservar acceso SSH
ufw --force enable
ok "Firewall configurado (puertos 80, 443 y SSH abiertos)."

# ---- 5. Verificar renovación automática ----
echo "[4/4] Verificando renovación automática..."
certbot renew --dry-run
ok "Renovación automática de certbot verificada (cron/systemd timer activo)."

echo
echo "============================================================"
echo -e "  ${GREEN}HTTPS configurado exitosamente!${NC}"
echo "  Accede en: https://${DOMAIN}"
echo
echo "  El certificado se renueva automáticamente vía systemd timer."
echo "  Verificar: systemctl status certbot.timer"
echo "============================================================"
