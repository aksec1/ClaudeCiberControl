@echo off
echo ============================================================
echo  Configuracion HTTPS con Let's Encrypt para Windows Server
echo ============================================================
echo.

REM ---- Verificar permisos de administrador ----
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: Este script debe ejecutarse como Administrador.
    pause
    exit /b 1
)

REM ---- Variables a editar antes de ejecutar ----
set DOMAIN=rendiciones.tuempresa.com
set EMAIL=admin@tuempresa.com
set NGINX_DIR=C:\nginx
set APP_DIR=C:\viaticos
set WINACME_DIR=C:\win-acme

echo [INFO] Dominio: %DOMAIN%
echo [INFO] Email:   %EMAIL%
echo.

REM ---- 1. Descargar win-acme si no existe ----
if not exist "%WINACME_DIR%\wacs.exe" (
    echo [1/5] Descargando win-acme...
    powershell -Command "Invoke-WebRequest -Uri 'https://github.com/win-acme/win-acme/releases/latest/download/win-acme.v2.2.9.1701.x64.pluggable.zip' -OutFile '%TEMP%\winacme.zip'"
    mkdir "%WINACME_DIR%" 2>nul
    powershell -Command "Expand-Archive -Path '%TEMP%\winacme.zip' -DestinationPath '%WINACME_DIR%' -Force"
    echo [OK] win-acme descargado en %WINACME_DIR%
) else (
    echo [1/5] win-acme ya instalado.
)

REM ---- 2. Descargar nginx para Windows si no existe ----
if not exist "%NGINX_DIR%\nginx.exe" (
    echo [2/5] Descargando nginx para Windows...
    powershell -Command "Invoke-WebRequest -Uri 'https://nginx.org/download/nginx-1.26.1.zip' -OutFile '%TEMP%\nginx.zip'"
    powershell -Command "Expand-Archive -Path '%TEMP%\nginx.zip' -DestinationPath 'C:\' -Force"
    ren C:\nginx-1.26.1 nginx 2>nul
    echo [OK] nginx descargado en %NGINX_DIR%
) else (
    echo [2/5] nginx ya instalado.
)

REM ---- 3. Copiar configuracion nginx ----
echo [3/5] Instalando configuracion nginx...
copy /Y "%APP_DIR%\nginx\nginx.conf" "%NGINX_DIR%\conf\nginx.conf"
powershell -Command "(Get-Content '%NGINX_DIR%\conf\nginx.conf') -replace 'rendiciones.tuempresa.com', '%DOMAIN%' | Set-Content '%NGINX_DIR%\conf\nginx.conf'"
echo [OK] Configuracion copiada y dominio actualizado.

REM ---- 4. Obtener certificado Let's Encrypt ----
echo [4/5] Solicitando certificado Let's Encrypt para %DOMAIN%...
echo       (El dominio debe apuntar a la IP de este servidor)
echo.
"%WINACME_DIR%\wacs.exe" ^
    --target manual ^
    --host %DOMAIN% ^
    --validation filesystem ^
    --webroot "%NGINX_DIR%\html" ^
    --store pemfiles ^
    --pemfilespath "C:\ProgramData\win-acme\acme-v02.api.letsencrypt.org\%DOMAIN%" ^
    --emailaddress %EMAIL% ^
    --accepttos

if %errorlevel% neq 0 (
    echo [ERROR] No se pudo obtener el certificado. Verifica que:
    echo   - El dominio %DOMAIN% apunta a la IP de este servidor
    echo   - El puerto 80 esta abierto en el firewall
    echo   - nginx esta corriendo (para el challenge HTTP-01)
    pause
    exit /b 1
)
echo [OK] Certificado obtenido.

REM ---- 5. Iniciar nginx y registrarlo como servicio ----
echo [5/5] Iniciando nginx...
cd /d "%NGINX_DIR%"
start nginx.exe
echo [OK] nginx iniciado.

REM Registrar nginx como servicio de Windows (usando NSSM si esta disponible)
where nssm >nul 2>&1
if %errorlevel% equ 0 (
    nssm install nginx "%NGINX_DIR%\nginx.exe" -p "%NGINX_DIR%\conf\nginx.conf"
    nssm start nginx
    echo [OK] nginx registrado como servicio de Windows.
) else (
    echo [INFO] Para registrar nginx como servicio instala NSSM: https://nssm.cc
)

REM ---- Reglas de firewall ----
echo Abriendo puertos 80 y 443 en el firewall de Windows...
netsh advfirewall firewall add rule name="HTTP (80)" dir=in action=allow protocol=TCP localport=80 >nul
netsh advfirewall firewall add rule name="HTTPS (443)" dir=in action=allow protocol=TCP localport=443 >nul
echo [OK] Puertos abiertos.

echo.
echo ============================================================
echo  HTTPS configurado exitosamente!
echo  Accede en: https://%DOMAIN%
echo.
echo  El certificado se renueva automaticamente via tarea
echo  programada de Windows (win-acme la crea al instalar).
echo ============================================================
pause
