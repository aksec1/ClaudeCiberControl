@echo off
echo ============================================
echo  Instalacion - Sistema de Rendicion de Gastos
echo ============================================

where python >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: Python no esta instalado o no esta en el PATH.
    echo Descarga Python 3.11+ desde https://python.org
    pause
    exit /b 1
)

echo [1/4] Creando entorno virtual...
python -m venv venv
call venv\Scripts\activate.bat

echo [2/4] Instalando dependencias...
pip install --upgrade pip
pip install -r requirements.txt

echo [3/4] Copiando configuracion...
if not exist .env (
    copy .env.example .env
    echo IMPORTANTE: Edita el archivo .env con tus datos de email y base de datos.
)

echo [4/4] Inicializando base de datos...
python init_db.py

echo.
echo ============================================
echo  Instalacion completada!
echo ============================================
echo  Para iniciar el servidor ejecuta: start_server.bat
echo  Usuario admin por defecto:
echo    Email:      admin@empresa.com
echo    Contrasena: Admin1234!
echo  CAMBIA LA CONTRASENA en el primer ingreso.
echo ============================================
pause
