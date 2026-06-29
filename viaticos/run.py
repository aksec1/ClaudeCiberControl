"""
Servidor de producción — Windows Server 2022 y Ubuntu Server 22.04
Usa Waitress (compatible con ambos SO).

Uso:
  Windows: python run.py
  Ubuntu:  venv/bin/python run.py
           (o lo inicia systemd automáticamente)
"""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))

from app import create_app
from waitress import serve

app = create_app()

if __name__ == "__main__":
    host = os.getenv("HOST", "127.0.0.1")   # solo localhost; nginx hace el proxy
    port = int(os.getenv("PORT", 5000))
    threads = int(os.getenv("THREADS", 8))

    print(f"Iniciando servidor en http://{host}:{port}  (threads={threads})")
    print("Presiona Ctrl+C para detener.")

    serve(app, host=host, port=port, threads=threads)
