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

## Requisitos

- Python 3.11+
- Windows Server 2022 (también compatible con Linux/macOS)

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

## Exponer en red local

Para que otros equipos accedan, abre el puerto 5000 en el Firewall de Windows:
```
netsh advfirewall firewall add rule name="Viaticos App" dir=in action=allow protocol=TCP localport=5000
```

Acceso desde la red: `http://IP-DEL-SERVIDOR:5000`

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
