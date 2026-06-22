"""
ClaudeCiberControl - Web Scanner Module
MITRE ATT&CK: TA0001 T1190 - Exploit Public-Facing Application
Checks: headers, SSL/TLS, cookies, forms, robots.txt, tech stack, common paths
"""

import re
import ssl
import socket
import datetime
import requests
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from config.settings import (
    HTTP_TIMEOUT, USER_AGENT, COMMON_PORTS,
    MITRE_TACTICS, NIST_CONTROLS, CIS_CONTROLS,
)

# Security headers that MUST be present
REQUIRED_SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "severity": "HIGH",
        "description": "HSTS no configurado - vulnerable a downgrade HTTP",
        "remediation": "Agregar: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
    },
    "Content-Security-Policy": {
        "severity": "HIGH",
        "description": "CSP ausente - XSS y data injection sin mitigacion",
        "remediation": "Implementar Content-Security-Policy restrictiva segun necesidades de la aplicacion",
    },
    "X-Frame-Options": {
        "severity": "MEDIUM",
        "description": "Sin proteccion contra Clickjacking",
        "remediation": "Agregar: X-Frame-Options: DENY o SAMEORIGIN",
    },
    "X-Content-Type-Options": {
        "severity": "MEDIUM",
        "description": "MIME sniffing no bloqueado",
        "remediation": "Agregar: X-Content-Type-Options: nosniff",
    },
    "Referrer-Policy": {
        "severity": "LOW",
        "description": "Politica de referrer no configurada - fuga de URLs internas",
        "remediation": "Agregar: Referrer-Policy: strict-origin-when-cross-origin",
    },
    "Permissions-Policy": {
        "severity": "LOW",
        "description": "Permissions-Policy ausente - acceso a APIs del navegador sin restriccion",
        "remediation": "Implementar Permissions-Policy para restringir acceso a camara, microfono, etc.",
    },
    "X-XSS-Protection": {
        "severity": "LOW",
        "description": "X-XSS-Protection no configurado (legacy - usar CSP como primaria)",
        "remediation": "Agregar: X-XSS-Protection: 1; mode=block",
    },
}

# Headers that SHOULD NOT be present (information leakage)
DANGEROUS_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version"]

# Common sensitive/admin paths to probe
SENSITIVE_PATHS = [
    "/.git/", "/.env", "/.htaccess", "/wp-admin/", "/admin/", "/administrator/",
    "/phpmyadmin/", "/phpinfo.php", "/info.php", "/test.php", "/backup/",
    "/robots.txt", "/sitemap.xml", "/.well-known/security.txt",
    "/api/", "/api/v1/", "/swagger/", "/swagger-ui.html", "/api-docs/",
    "/actuator/", "/actuator/health", "/actuator/env", "/actuator/beans",
    "/console/", "/manager/html", "/jmx-console/", "/.DS_Store",
    "/crossdomain.xml", "/clientaccesspolicy.xml",
    "/server-status", "/server-info",
]

# SSL/TLS weak ciphers and protocols
WEAK_SSL_PROTOCOLS = ["SSLv2", "SSLv3", "TLSv1", "TLSv1.1"]

# Cookie flags required
REQUIRED_COOKIE_FLAGS = {"Secure", "HttpOnly", "SameSite"}


class WebScanner:
    """
    Web application scanner performing:
    - Security headers audit
    - SSL/TLS configuration analysis
    - Cookie security analysis
    - Sensitive path discovery
    - Technology fingerprinting
    - Form analysis (CSRF protection)
    - Information disclosure checks
    """

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
        target = target.strip()
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
            "id": fid,
            "module": "WebScanner",
            "title": title,
            "severity": severity,
            "description": description,
            "evidence": evidence,
            "target": url or self.host,
            "url": url,
            "category": category,
            "mitre": tactic,
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
                self._log(f"Error accediendo {url}: {e}", "ERROR")

        # SSL/TLS check for HTTPS targets
        if any("https://" in u for u in self.base_urls):
            self._check_ssl_tls()

        return self.findings

    def _discover_web_endpoints(self):
        schemes_ports = [
            ("https", 443), ("http", 80),
            ("https", 8443), ("http", 8080),
            ("http", 8000), ("http", 8888),
        ]
        for scheme, port in schemes_ports:
            url = f"{scheme}://{self.host}:{port}" if port not in (80, 443) else f"{scheme}://{self.host}"
            try:
                resp = self.session.get(url, timeout=5, allow_redirects=True)
                if resp.status_code < 500:
                    self.base_urls.append(url)
                    self._log(f"Endpoint web activo: {url} (HTTP {resp.status_code})", "SUCCESS")
            except Exception:
                pass

        if not self.base_urls:
            self._log("No se encontraron endpoints web activos", "WARNING")

    def _check_security_headers(self, url: str, resp: requests.Response):
        missing = []
        for header, info in REQUIRED_SECURITY_HEADERS.items():
            if header not in resp.headers:
                missing.append((header, info))
                self.findings.append(
                    self._finding(
                        f"WEB-HDR-{header[:15].upper().replace('-', '_')}",
                        f"Header de seguridad ausente: {header}",
                        info["severity"],
                        info["description"],
                        "missing_security_headers",
                        f"URL: {url}\nHeader faltante: {header}",
                        url,
                        [info["remediation"]],
                    )
                )
        if missing:
            self._log(f"  {len(missing)} headers de seguridad faltantes en {url}", "WARNING")

    def _check_dangerous_headers(self, url: str, resp: requests.Response):
        for header in DANGEROUS_HEADERS:
            value = resp.headers.get(header, "")
            if value:
                self.findings.append(
                    self._finding(
                        f"WEB-HDR-LEAK-{header[:10].upper()}",
                        f"Header informativo expuesto: {header}: {value}",
                        "LOW",
                        f"El header '{header}' expone informacion de tecnologia: {value}",
                        "info_disclosure",
                        f"Header: {header}: {value}",
                        url,
                        [f"Eliminar o enmascarar el header {header} en la configuracion del servidor"],
                    )
                )

    def _check_cookies(self, url: str, resp: requests.Response):
        for cookie in resp.cookies:
            missing_flags = []
            if not cookie.secure:
                missing_flags.append("Secure")
            if not cookie.has_nonstandard_attr("HttpOnly"):
                missing_flags.append("HttpOnly")
            samesite = cookie._rest.get("SameSite", "")
            if not samesite:
                missing_flags.append("SameSite")

            if missing_flags:
                severity = "HIGH" if "Secure" in missing_flags or "HttpOnly" in missing_flags else "MEDIUM"
                self.findings.append(
                    self._finding(
                        f"WEB-COOKIE-{cookie.name[:15].upper()}",
                        f"Cookie insegura: {cookie.name}",
                        severity,
                        f"La cookie '{cookie.name}' no tiene los flags: {', '.join(missing_flags)}",
                        "missing_security_headers",
                        f"Cookie: {cookie.name}\nFlags faltantes: {', '.join(missing_flags)}",
                        url,
                        [f"Configurar cookie con flags: {'; '.join(REQUIRED_COOKIE_FLAGS)}"],
                    )
                )
                self._log(f"  Cookie insegura: {cookie.name} - falta {missing_flags}", "WARNING")

    def _check_content(self, url: str, resp: requests.Response):
        content = resp.text
        ct = resp.headers.get("Content-Type", "")

        if "text/html" not in ct:
            return

        soup = BeautifulSoup(content, "html.parser")

        # Check for forms without CSRF protection
        forms = soup.find_all("form")
        for form in forms:
            inputs = form.find_all("input")
            has_csrf = any(
                inp.get("name", "").lower() in ("csrf_token", "_token", "csrfmiddlewaretoken",
                                                "_csrf", "authenticity_token", "csrf")
                for inp in inputs
            )
            if not has_csrf and form.get("method", "get").lower() == "post":
                self.findings.append(
                    self._finding(
                        f"WEB-CSRF-{len(self.findings):03d}",
                        "Formulario POST sin proteccion CSRF aparente",
                        "MEDIUM",
                        "Se detecta un formulario POST sin token CSRF visible. Puede ser vulnerable a CSRF.",
                        "missing_security_headers",
                        f"URL: {url}\nForm action: {form.get('action', 'N/A')}",
                        url,
                        ["Implementar tokens CSRF sincronizados en todos los formularios POST",
                         "Usar el patron Double Submit Cookie como alternativa"],
                    )
                )

        # Check for sensitive data in comments
        comments = soup.find_all(string=lambda t: isinstance(t, str) and "<!--" not in str(t))
        html_comments = re.findall(r"<!--(.*?)-->", content, re.DOTALL)
        for comment in html_comments:
            if any(kw in comment.lower() for kw in ["password", "passwd", "secret", "api_key",
                                                      "token", "credential", "todo", "fixme"]):
                self.findings.append(
                    self._finding(
                        f"WEB-COMMENT-{len(self.findings):03d}",
                        "Informacion sensible en comentarios HTML",
                        "MEDIUM",
                        "Se encontraron comentarios HTML que pueden revelar informacion sensible",
                        "info_disclosure",
                        f"Comentario: {comment[:200]}",
                        url,
                        ["Eliminar todos los comentarios de desarrollo del codigo de produccion"],
                    )
                )

        # Check for directory listing
        if any(phrase in content for phrase in
               ["Index of /", "Directory listing for", "Parent Directory"]):
            self.findings.append(
                self._finding(
                    f"WEB-DIRLIST-{len(self.findings):03d}",
                    "Directory Listing habilitado",
                    "MEDIUM",
                    "El servidor expone el listado de directorios permitiendo enumerar archivos",
                    "directory_listing",
                    f"URL: {url}",
                    url,
                    ["Deshabilitar Options -Indexes en Apache o autoindex off en Nginx",
                     "Asegurar que cada directorio tenga un index.html"],
                )
            )
            self._log(f"  Directory listing en: {url}", "WARNING")

    def _probe_sensitive_paths(self, base_url: str):
        self._log(f"  Probando {len(SENSITIVE_PATHS)} rutas sensibles...")
        for path in SENSITIVE_PATHS:
            url = urljoin(base_url, path)
            try:
                resp = self.session.get(url, timeout=5, allow_redirects=False)
                if resp.status_code in (200, 301, 302, 403):
                    severity = "HIGH" if resp.status_code == 200 else "MEDIUM"
                    if path in ("/.git/", "/.env", "/phpinfo.php", "/info.php"):
                        severity = "CRITICAL"
                    elif path in ("/robots.txt", "/sitemap.xml"):
                        severity = "INFO"

                    self.findings.append(
                        self._finding(
                            f"WEB-PATH-{path.strip('/').replace('/', '_').upper()[:20]}",
                            f"Ruta sensible accesible: {path}",
                            severity,
                            f"La ruta '{path}' responde con HTTP {resp.status_code}",
                            "info_disclosure" if severity in ("LOW", "INFO", "MEDIUM") else "directory_listing",
                            f"URL: {url}\nStatus: {resp.status_code}\nSize: {len(resp.content)} bytes",
                            url,
                            ["Restringir acceso a rutas administrativas con autenticacion",
                             "Eliminar archivos de configuracion y backup del servidor web",
                             "Implementar reglas de firewall para bloquear acceso externo"],
                        )
                    )
                    self._log(f"  [{resp.status_code}] {url}", "WARNING" if severity != "INFO" else "INFO")
            except requests.RequestException:
                pass

    def _check_ssl_tls(self):
        self._log("Analizando configuracion SSL/TLS...")
        host = self.host
        port = 443

        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            with socket.create_connection((host, port), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    version = ssock.version()

                    self._log(f"  TLS version: {version}, Cipher: {cipher[0]}")

                    # Check TLS version
                    if version in ("TLSv1", "TLSv1.1"):
                        self.findings.append(
                            self._finding(
                                "WEB-SSL-WEAKVER",
                                f"Version TLS debil: {version}",
                                "HIGH",
                                f"El servidor usa {version} que es obsoleto y vulnerable (POODLE, BEAST)",
                                "weak_ssl",
                                f"TLS Version: {version}",
                                f"https://{host}",
                                ["Deshabilitar TLS 1.0 y 1.1 - usar solo TLS 1.2 y TLS 1.3",
                                 "Configurar cipher suites fuertes segun guia NIST SP 800-52"],
                            )
                        )

                    # Certificate expiry
                    if cert:
                        not_after = cert.get("notAfter", "")
                        if not_after:
                            exp_date = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                            days_left = (exp_date - datetime.datetime.utcnow()).days
                            if days_left < 30:
                                sev = "CRITICAL" if days_left < 7 else "HIGH"
                                self.findings.append(
                                    self._finding(
                                        "WEB-SSL-CERTEXP",
                                        f"Certificado SSL expira en {days_left} dias",
                                        sev,
                                        f"El certificado SSL expira el {not_after}",
                                        "weak_ssl",
                                        f"Expiration: {not_after} ({days_left} dias restantes)",
                                        f"https://{host}",
                                        ["Renovar el certificado SSL/TLS inmediatamente"],
                                    )
                                )

                    # Weak cipher check
                    if cipher:
                        cipher_name = cipher[0].lower()
                        weak_ciphers = ["rc4", "des", "3des", "null", "anon", "md5", "export"]
                        for wc in weak_ciphers:
                            if wc in cipher_name:
                                self.findings.append(
                                    self._finding(
                                        f"WEB-SSL-CIPHER-{wc.upper()}",
                                        f"Cipher suite debil en uso: {cipher[0]}",
                                        "HIGH",
                                        f"El servidor negocia el cipher debil '{cipher[0]}'",
                                        "weak_ssl",
                                        f"Cipher: {cipher[0]}",
                                        f"https://{host}",
                                        ["Deshabilitar cipher suites debiles",
                                         "Configurar solo ECDHE y DHE para forward secrecy"],
                                    )
                                )

        except Exception as e:
            self._log(f"  Error SSL: {e}", "WARNING")
