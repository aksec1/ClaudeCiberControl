"""
ClaudeCiberControl - Web Scanner Module
MITRE ATT&CK: TA0001 T1190 - Exploit Public-Facing Application
"""

import re
import ssl
import socket
import datetime
import requests
from urllib.parse import urljoin
from bs4 import BeautifulSoup
from config.settings import HTTP_TIMEOUT, USER_AGENT, MITRE_TACTICS, NIST_CONTROLS, CIS_CONTROLS

REQUIRED_SECURITY_HEADERS = {
    "Strict-Transport-Security": {"severity": "HIGH", "description": "HSTS no configurado",
        "remediation": "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"},
    "Content-Security-Policy": {"severity": "HIGH", "description": "CSP ausente - XSS sin mitigacion",
        "remediation": "Implementar Content-Security-Policy restrictiva"},
    "X-Frame-Options": {"severity": "MEDIUM", "description": "Sin proteccion contra Clickjacking",
        "remediation": "X-Frame-Options: DENY"},
    "X-Content-Type-Options": {"severity": "MEDIUM", "description": "MIME sniffing no bloqueado",
        "remediation": "X-Content-Type-Options: nosniff"},
    "Referrer-Policy": {"severity": "LOW", "description": "Politica de referrer no configurada",
        "remediation": "Referrer-Policy: strict-origin-when-cross-origin"},
    "Permissions-Policy": {"severity": "LOW", "description": "Permissions-Policy ausente",
        "remediation": "Implementar Permissions-Policy para restringir APIs del navegador"},
    "X-XSS-Protection": {"severity": "LOW", "description": "X-XSS-Protection no configurado",
        "remediation": "X-XSS-Protection: 1; mode=block"},
}

DANGEROUS_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version"]

SENSITIVE_PATHS = [
    "/.git/", "/.env", "/.htaccess", "/wp-admin/", "/admin/", "/administrator/",
    "/phpmyadmin/", "/phpinfo.php", "/info.php", "/test.php", "/backup/",
    "/robots.txt", "/sitemap.xml", "/.well-known/security.txt",
    "/api/", "/api/v1/", "/swagger/", "/swagger-ui.html", "/api-docs/",
    "/actuator/", "/actuator/health", "/actuator/env", "/actuator/beans",
    "/console/", "/manager/html", "/jmx-console/", "/.DS_Store",
    "/crossdomain.xml", "/server-status", "/server-info",
]


class WebScanner:
    def __init__(self, target: str, verbose: bool = True):
        self.target = target
        self.verbose = verbose
        self.host = self._extract_host(target)
        self.base_urls: list[str] = []
        self.findings: list[dict] = []
        self.session = requests.Session()
        self.session.headers["User-Agent"] = USER_AGENT
        self.session.verify = False
        requests.packages.urllib3.disable_warnings()

    def _extract_host(self, target: str) -> str:
        for prefix in ("https://", "http://"):
            if target.startswith(prefix):
                target = target[len(prefix):]
        return target.split("/")[0].split(":")[0]

    def _log(self, msg: str, level: str = "INFO"):
        colors = {"INFO": "\033[96m", "WARNING": "\033[93m", "ERROR": "\033[91m", "SUCCESS": "\033[92m"}
        if self.verbose:
            print(f"{colors.get(level, '')}  [WEB] {msg}\033[0m")

    def _finding(self, fid: str, title: str, severity: str, description: str,
                 category: str, evidence: str, url: str = "",
                 remediation: list[str] | None = None) -> dict:
        tactic = MITRE_TACTICS.get(category, {})
        return {
            "id": fid, "module": "WebScanner", "title": title,
            "severity": severity, "description": description,
            "evidence": evidence, "target": url or self.host, "url": url,
            "category": category, "mitre": tactic,
            "nist": NIST_CONTROLS.get(category, []),
            "cis": CIS_CONTROLS.get(category, []),
            "timestamp": datetime.datetime.now().isoformat(),
            "remediation": remediation or tactic.get("mitigations", []),
        }

    def scan(self) -> list[dict]:
        self._discover_web_endpoints()
        for url in self.base_urls:
            self._log(f"Analizando: {url}")
            try:
                resp = self.session.get(url, timeout=HTTP_TIMEOUT, allow_redirects=True)
                self._check_security_headers(url, resp)
                self._check_dangerous_headers(url, resp)
                self._check_cookies(url, resp)
                self._check_content(url, resp)
                self._probe_sensitive_paths(url)
            except requests.RequestException as e:
                self._log(f"Error: {e}", "ERROR")
        if any("https://" in u for u in self.base_urls):
            self._check_ssl_tls()
        return self.findings

    def _discover_web_endpoints(self):
        for scheme, port in [("https", 443), ("http", 80), ("https", 8443), ("http", 8080)]:
            url = f"{scheme}://{self.host}:{port}" if port not in (80, 443) else f"{scheme}://{self.host}"
            try:
                resp = self.session.get(url, timeout=5, allow_redirects=True)
                if resp.status_code < 500:
                    self.base_urls.append(url)
                    self._log(f"Endpoint activo: {url} (HTTP {resp.status_code})", "SUCCESS")
            except Exception:
                pass
        if not self.base_urls:
            self._log("No se encontraron endpoints web activos", "WARNING")

    def _check_security_headers(self, url: str, resp: requests.Response):
        for header, info in REQUIRED_SECURITY_HEADERS.items():
            if header not in resp.headers:
                self.findings.append(self._finding(
                    f"WEB-HDR-{header[:15].upper().replace('-', '_')}",
                    f"Header de seguridad ausente: {header}",
                    info["severity"], info["description"],
                    "missing_security_headers",
                    f"URL: {url}\nHeader faltante: {header}", url,
                    [info["remediation"]]))

    def _check_dangerous_headers(self, url: str, resp: requests.Response):
        for header in DANGEROUS_HEADERS:
            value = resp.headers.get(header, "")
            if value:
                self.findings.append(self._finding(
                    f"WEB-HDR-LEAK-{header[:10].upper()}",
                    f"Header informativo expuesto: {header}: {value}",
                    "LOW", f"Header '{header}' expone informacion: {value}",
                    "info_disclosure", f"Header: {header}: {value}", url,
                    [f"Eliminar header {header} en la configuracion del servidor"]))

    def _check_cookies(self, url: str, resp: requests.Response):
        for cookie in resp.cookies:
            missing = []
            if not cookie.secure:
                missing.append("Secure")
            if not cookie.has_nonstandard_attr("HttpOnly"):
                missing.append("HttpOnly")
            if not cookie._rest.get("SameSite", ""):
                missing.append("SameSite")
            if missing:
                severity = "HIGH" if "Secure" in missing or "HttpOnly" in missing else "MEDIUM"
                self.findings.append(self._finding(
                    f"WEB-COOKIE-{cookie.name[:15].upper()}",
                    f"Cookie insegura: {cookie.name}",
                    severity, f"Cookie '{cookie.name}' sin flags: {', '.join(missing)}",
                    "missing_security_headers",
                    f"Cookie: {cookie.name} - Falta: {', '.join(missing)}", url,
                    [f"Configurar cookie con flags: Secure; HttpOnly; SameSite=Strict"]))

    def _check_content(self, url: str, resp: requests.Response):
        if "text/html" not in resp.headers.get("Content-Type", ""):
            return
        soup = BeautifulSoup(resp.text, "html.parser")
        for form in soup.find_all("form"):
            inputs = form.find_all("input")
            has_csrf = any(inp.get("name", "").lower() in
                ("csrf_token", "_token", "csrfmiddlewaretoken", "_csrf", "authenticity_token")
                for inp in inputs)
            if not has_csrf and form.get("method", "get").lower() == "post":
                self.findings.append(self._finding(
                    f"WEB-CSRF-{len(self.findings):03d}",
                    "Formulario POST sin proteccion CSRF",
                    "MEDIUM", "Formulario POST sin token CSRF visible",
                    "missing_security_headers",
                    f"Form action: {form.get('action', 'N/A')}", url,
                    ["Implementar tokens CSRF en todos los formularios POST"]))
        for comment in re.findall(r"<!--(.*?)-->", resp.text, re.DOTALL):
            if any(kw in comment.lower() for kw in ["password", "secret", "api_key", "token", "credential"]):
                self.findings.append(self._finding(
                    f"WEB-COMMENT-{len(self.findings):03d}",
                    "Informacion sensible en comentarios HTML",
                    "MEDIUM", "Comentarios HTML con keywords sensibles",
                    "info_disclosure", f"Comentario: {comment[:200]}", url,
                    ["Eliminar comentarios de desarrollo del codigo de produccion"]))
        if any(p in resp.text for p in ["Index of /", "Directory listing", "Parent Directory"]):
            self.findings.append(self._finding(
                f"WEB-DIRLIST-{len(self.findings):03d}",
                "Directory Listing habilitado", "MEDIUM",
                "El servidor expone listado de directorios",
                "directory_listing", f"URL: {url}", url,
                ["Deshabilitar Options -Indexes en Apache / autoindex off en Nginx"]))

    def _probe_sensitive_paths(self, base_url: str):
        for path in SENSITIVE_PATHS:
            url = urljoin(base_url, path)
            try:
                resp = self.session.get(url, timeout=5, allow_redirects=False)
                if resp.status_code in (200, 301, 302, 403):
                    severity = "CRITICAL" if path in ("/.git/", "/.env", "/phpinfo.php") else \
                               "INFO" if path in ("/robots.txt", "/sitemap.xml") else \
                               "HIGH" if resp.status_code == 200 else "MEDIUM"
                    self.findings.append(self._finding(
                        f"WEB-PATH-{path.strip('/').replace('/', '_').upper()[:20]}",
                        f"Ruta sensible accesible: {path}",
                        severity, f"Ruta '{path}' responde HTTP {resp.status_code}",
                        "info_disclosure", f"URL: {url} Status: {resp.status_code}", url,
                        ["Restringir acceso a rutas administrativas",
                         "Eliminar archivos de configuracion del servidor web"]))
                    self._log(f"  [{resp.status_code}] {url}",
                              "WARNING" if severity != "INFO" else "INFO")
            except requests.RequestException:
                pass

    def _check_ssl_tls(self):
        self._log("Analizando SSL/TLS...")
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((self.host, 443), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=self.host) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    version = ssock.version()
                    self._log(f"  TLS: {version}, Cipher: {cipher[0]}")
                    if version in ("TLSv1", "TLSv1.1"):
                        self.findings.append(self._finding(
                            "WEB-SSL-WEAKVER", f"Version TLS debil: {version}",
                            "HIGH", f"Servidor usa {version} (obsoleto, vulnerable a POODLE/BEAST)",
                            "weak_ssl", f"TLS: {version}", f"https://{self.host}",
                            ["Usar solo TLS 1.2 y TLS 1.3"]))
                    if cert:
                        not_after = cert.get("notAfter", "")
                        if not_after:
                            exp = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                            days = (exp - datetime.datetime.utcnow()).days
                            if days < 30:
                                self.findings.append(self._finding(
                                    "WEB-SSL-CERTEXP", f"Certificado expira en {days} dias",
                                    "CRITICAL" if days < 7 else "HIGH",
                                    f"Certificado SSL expira el {not_after}",
                                    "weak_ssl", f"Expira: {not_after}", f"https://{self.host}",
                                    ["Renovar certificado SSL/TLS inmediatamente"]))
                    if cipher and any(w in cipher[0].lower() for w in ["rc4", "des", "3des", "null", "anon"]):
                        self.findings.append(self._finding(
                            "WEB-SSL-WEAKCIPHER", f"Cipher debil: {cipher[0]}",
                            "HIGH", f"Cipher suite debil en uso: {cipher[0]}",
                            "weak_ssl", f"Cipher: {cipher[0]}", f"https://{self.host}",
                            ["Deshabilitar cipher suites debiles - usar ECDHE/DHE"]))
        except Exception as e:
            self._log(f"  Error SSL: {e}", "WARNING")
