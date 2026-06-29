"""
Servidor de producción para Windows Server 2022 usando Waitress.
Uso: python run_windows.py

Para Ubuntu usa run.py (misma lógica, HOST por defecto es 127.0.0.1
para que solo nginx pueda acceder).
"""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))

from app import create_app
from waitress import serve

app = create_app()

if __name__ == "__main__":
    # En Windows sin reverse proxy escucha en todas las interfaces.
    # En Ubuntu con nginx usar run.py (HOST=127.0.0.1).
    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", 5000))
    threads = int(os.getenv("THREADS", 8))

    print(f"Iniciando servidor en http://{host}:{port}  (threads={threads})")
    print("Presiona Ctrl+C para detener.")

    serve(app, host=host, port=port, threads=threads)
