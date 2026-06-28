"""
Servicio de Windows para ejecutar la aplicación en background.
Requiere: pip install pywin32
Instalar:  python viaticos_service.py install
Iniciar:   python viaticos_service.py start
Detener:   python viaticos_service.py stop
Desinstalar: python viaticos_service.py remove
"""
import sys
import os

try:
    import win32serviceutil
    import win32service
    import win32event
    import servicemanager
    HAS_WIN32 = True
except ImportError:
    HAS_WIN32 = False

if HAS_WIN32:
    class ViaticosService(win32serviceutil.ServiceFramework):
        _svc_name_ = "ViaticosApp"
        _svc_display_name_ = "Sistema Rendición de Viáticos"
        _svc_description_ = "Plataforma web de rendición de gastos y viáticos."

        def __init__(self, args):
            win32serviceutil.ServiceFramework.__init__(self, args)
            self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)
            self._server = None

        def SvcStop(self):
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
            win32event.SetEvent(self.hWaitStop)

        def SvcDoRun(self):
            servicemanager.LogMsg(
                servicemanager.EVENTLOG_INFORMATION_TYPE,
                servicemanager.PYS_SERVICE_STARTED,
                (self._svc_name_, ""),
            )
            sys.path.insert(0, os.path.dirname(__file__))
            from app import create_app
            from waitress import serve
            import threading

            app = create_app()
            host = os.getenv("HOST", "0.0.0.0")
            port = int(os.getenv("PORT", 5000))

            t = threading.Thread(target=serve, args=(app,), kwargs={"host": host, "port": port, "threads": 8}, daemon=True)
            t.start()
            win32event.WaitForSingleObject(self.hWaitStop, win32event.INFINITE)

    if __name__ == "__main__":
        win32serviceutil.HandleCommandLine(ViaticosService)
else:
    print("pywin32 no está instalado. Este script solo funciona en Windows.")
    print("Instala con: pip install pywin32")
