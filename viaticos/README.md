# Sistema de Rendición de Viáticos y Beneficios

Plataforma web para gestión de rendiciones de gastos (viáticos, almuerzos, transporte) con adjuntos de tickets/fotos, flujo de aprobación y notificaciones por email.

## Características

- Subida de imágenes (JPG, PNG) y PDF como comprobantes
- Tipos de gasto: Viático, Almuerzo, Transporte, Alojamiento, Otro
- Flujo: Borrador → Enviado → En Revisión → Aprobado/Rechazado → Pagado
- Notificaciones automáticas por email en cada cambio de estado
- Panel de administración para aprobar, rechazar y marcar pagos
- Gestión de usuarios con roles (admin / empleado)
- Cuenta bancaria del empleado para trazabilidad del pago
- **HTTPS con Let's Encrypt** (certificado gratuito, renovación automática)

## Requisitos

- Python 3.11+
- **Windows Server 2022** o **Ubuntu Server 22.04 LTS**

---

## Instalación en Ubuntu Server 22.04 LTS

### Instalación automática (recomendada)

```bash
# 1. Clonar el repositorio o copiar la carpeta viaticos/ al servidor
git clone https://github.com/aksec1/ClaudeCiberControl.git
cd ClaudeCiberControl/viaticos

# 2. Ejecutar el instalador como root
sudo bash install_ubuntu.sh

# 3. Editar configuración (email, empresa, etc.)
sudo nano /opt/viaticos/.env

# 4. Iniciar el servicio
sudo systemctl start viaticos
sudo systemctl status viaticos
```

### Configurar HTTPS con Let's Encrypt (Ubuntu)

```bash
# Editar dominio y email en el script
sudo nano /opt/viaticos/nginx/setup_https_ubuntu.sh

# Ejecutar (requiere que el dominio apunte a este servidor)
sudo bash /opt/viaticos/nginx/setup_https_ubuntu.sh
```

El script hace todo automáticamente:
- Instala y configura **nginx** como reverse proxy
- Solicita el certificado gratuito con **Certbot** (Let's Encrypt)
- Configura la redirección HTTP → HTTPS
- Activa el **systemd timer** de renovación automática cada 60 días

### Comandos útiles (Ubuntu)

```bash
# Ver logs en tiempo real
sudo journalctl -u viaticos -f

# Reiniciar la app
sudo systemctl restart viaticos

# Estado del servicio
sudo systemctl status viaticos

# Renovar certificado manualmente
sudo certbot renew

# Estado del timer de renovación automática
systemctl status certbot.timer
```

---

## Instalación en Windows Server 2022

```bat
# 1. Clonar o copiar la carpeta viaticos/ al servidor

# 2. Ejecutar el instalador (doble clic o cmd como Administrador)
install_windows.bat

# 3. Editar configuración
notepad .env

# 4. Iniciar el servidor
start_server.bat
```

El sistema queda disponible en `http://localhost:5000`

## Configuración (.env)

```env
SECRET_KEY=clave-secreta-de-64-caracteres
DATABASE_URL=sqlite:///viaticos.db

MAIL_SERVER=smtp.gmail.com
MAIL_PORT=587
MAIL_USE_TLS=True
MAIL_USERNAME=tu-correo@empresa.com
MAIL_PASSWORD=tu-app-password

COMPANY_NAME=Mi Empresa S.A.
ADMIN_EMAIL=admin@empresa.com
```

### Email con Gmail
Activa "Contraseñas de aplicación" en tu cuenta Google y usa esa contraseña en `MAIL_PASSWORD`.

### Base de datos SQL Server (opcional)
```env
DATABASE_URL=mssql+pyodbc://usuario:password@servidor/BaseDatos?driver=ODBC+Driver+17+for+SQL+Server
```
Agrega `pyodbc` a requirements.txt.

## Instalar como Servicio de Windows

```bat
venv\Scripts\activate
python viaticos_service.py install
python viaticos_service.py start
```

## HTTPS con Let's Encrypt (Recomendado para producción)

### Arquitectura recomendada

```
Internet  →  nginx (puerto 443, TLS)  →  Flask/Waitress (puerto 5000, localhost)
               ↕ cert Let's Encrypt
             win-acme (renovación automática)
```

### Requisitos previos
- Dominio propio (ej: `rendiciones.tuempresa.com`) apuntando a la IP del servidor
- Puerto 80 y 443 abiertos en el firewall del router/ISP

### Instalación automática

```bat
# Como Administrador:
# 1. Edita las variables DOMAIN y EMAIL al inicio del script
notepad nginx\setup_https_windows.bat

# 2. Ejecuta el script (descarga nginx + win-acme, obtiene certificado)
nginx\setup_https_windows.bat
```

El script:
1. Descarga **nginx** (reverse proxy) y **win-acme** (cliente Let's Encrypt)
2. Solicita el certificado TLS gratuito para tu dominio
3. Configura nginx para redirigir HTTP → HTTPS
4. Crea tarea programada de Windows para renovar el certificado automáticamente (cada 60 días)

### Instalación manual paso a paso

**1. Instalar nginx para Windows**
```
Descargar: https://nginx.org/en/download.html (nginx/Windows)
Extraer en: C:\nginx\
```

**2. Copiar y ajustar configuración**
```bat
copy nginx\nginx.conf C:\nginx\conf\nginx.conf
# Editar: cambiar "rendiciones.tuempresa.com" por tu dominio real
# Editar: ajustar rutas de certificados y archivos estáticos
```

**3. Obtener certificado con win-acme**
```
Descargar: https://www.win-acme.com/
Extraer en: C:\win-acme\

# Ejecutar como Administrador:
C:\win-acme\wacs.exe --target manual --host rendiciones.tuempresa.com \
  --validation filesystem --webroot C:\nginx\html \
  --store pemfiles --emailaddress admin@tuempresa.com --accepttos
```

**4. Iniciar nginx**
```bat
cd C:\nginx
nginx.exe
```

**5. Abrir puertos en Firewall**
```bat
netsh advfirewall firewall add rule name="HTTP"  dir=in action=allow protocol=TCP localport=80
netsh advfirewall firewall add rule name="HTTPS" dir=in action=allow protocol=TCP localport=443
```

El sistema queda disponible en `https://rendiciones.tuempresa.com`

### Opción B: SSL directo (sin nginx, solo red interna)

Útil si el portal es solo para la red local y no necesitas dominio público:

```bat
# Con certificado autofirmado (genera advertencia en el navegador):
venv\Scripts\activate
python run_https.py --selfsigned

# Con certificado propio:
python run_https.py --cert C:\ruta\cert.pem --key C:\ruta\key.pem
```

> **Nota**: Para certificados Let's Encrypt se requiere un dominio público. Para redes internas, considera usar un certificado de una CA interna (Active Directory Certificate Services) o aceptar el certificado autofirmado en los navegadores de la empresa.

### Renovación automática

win-acme crea automáticamente una **tarea programada de Windows** que renueva el certificado antes de que venza (cada ~60 días). No requiere intervención manual.

## Usuarios por defecto

| Email | Contraseña | Rol |
|-------|-----------|-----|
| admin@empresa.com | Admin1234! | Administrador |

**Cambia la contraseña en el primer ingreso.**

## Flujo de trabajo

1. Empleado crea una rendición (título, destino, fechas)
2. Agrega ítems con monto, tipo, fecha y adjunta ticket/foto/PDF
3. Envía la rendición → email de confirmación al empleado
4. Admin revisa comprobantes, aprueba o rechaza → email al empleado
5. Admin marca como pagado → email informando acreditación del dinero
