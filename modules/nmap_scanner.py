"""
ClaudeCiberControl - Nmap Scanner Module (potenciado)
MITRE ATT&CK: TA0043 T1046 - Network Service Discovery
NIST SP 800-115: Technical Guide to Information Security Testing
"""

import nmap
import datetime
from config.settings import (
    NMAP_DEFAULT_ARGS, NMAP_FAST_ARGS, NMAP_FULL_ARGS,
    NMAP_VULN_ARGS, NMAP_UDP_ARGS, NMAP_TIMEOUT,
    MITRE_TACTICS, NIST_CONTROLS, CIS_CONTROLS,
)

# Known vulnerable versions: product -> (max_safe_version, CVE, CVSS, severity)
VULNERABLE_VERSIONS: dict[str, tuple] = {
    "apache httpd": ("2.4.57", "CVE-2023-25690", 9.8, "CRITICAL"),
    "nginx": ("1.24.0", "CVE-2021-23017", 7.7, "HIGH"),
    "openssh": ("8.9", "CVE-2023-38408", 9.8, "CRITICAL"),
    "vsftpd": ("3.0.3", "CVE-2021-3618", 7.4, "HIGH"),
    "proftpd": ("1.3.7", "CVE-2019-12815", 9.8, "CRITICAL"),
    "openssl": ("3.1.0", "CVE-2022-0778", 7.5, "HIGH"),
    "php": ("8.2.0", "CVE-2023-0568", 8.8, "HIGH"),
    "iis": ("10.0", "CVE-2022-21907", 9.8, "CRITICAL"),
    "tomcat": ("10.1.0", "CVE-2023-28708", 6.5, "MEDIUM"),
    "mysql": ("8.0.32", "CVE-2023-21977", 4.9, "MEDIUM"),
    "postgresql": ("15.2", "CVE-2023-2454", 7.2, "HIGH"),
    "redis": ("7.0.10", "CVE-2023-28856", 6.5, "MEDIUM"),
    "mongodb": ("6.0.5", "CVE-2021-20328", 6.4, "MEDIUM"),
    "smb": ("3.1.1", "CVE-2020-0796", 10.0, "CRITICAL"),
    "rdp": ("10.0", "CVE-2019-0708", 9.8, "CRITICAL"),
    "telnetd": ("0.17", "CVE-2020-10188", 9.8, "CRITICAL"),
}

# High-risk port categories
HIGH_RISK_PORTS: dict[int, dict] = {
    21: {"service": "FTP", "risk": "Transferencia sin cifrar, credenciales en claro", "severity": "HIGH"},
    23: {"service": "Telnet", "risk": "Protocolo inseguro - credenciales y datos en texto plano", "severity": "CRITICAL"},
    25: {"service": "SMTP", "risk": "Relay abierto potencial", "severity": "MEDIUM"},
    53: {"service": "DNS", "risk": "Transferencia de zona o amplificacion DNS", "severity": "MEDIUM"},
    69: {"service": "TFTP", "risk": "Sin autenticacion, acceso anonimo", "severity": "HIGH"},
    110: {"service": "POP3", "risk": "Correo sin cifrar", "severity": "MEDIUM"},
    111: {"service": "RPC", "risk": "Remote Procedure Call expuesto", "severity": "HIGH"},
    135: {"service": "MSRPC", "risk": "Endpoint Mapper de Windows expuesto", "severity": "HIGH"},
    137: {"service": "NetBIOS", "risk": "Enumeracion de recursos compartidos", "severity": "HIGH"},
    139: {"service": "NetBIOS-SSN", "risk": "SMB sin cifrar", "severity": "HIGH"},
    143: {"service": "IMAP", "risk": "Correo sin cifrar", "severity": "MEDIUM"},
    161: {"service": "SNMP", "risk": "Community string publica - divulgacion de informacion", "severity": "HIGH"},
    389: {"service": "LDAP", "risk": "Directorio sin cifrar", "severity": "MEDIUM"},
    443: {"service": "HTTPS", "risk": "Revisar configuracion SSL/TLS", "severity": "INFO"},
    445: {"service": "SMB", "risk": "EternalBlue/PrintNightmare vectores criticos", "severity": "CRITICAL"},
    512: {"service": "rexec", "risk": "Ejecucion remota insegura", "severity": "CRITICAL"},
    513: {"service": "rlogin", "risk": "Login remoto inseguro", "severity": "CRITICAL"},
    514: {"service": "RSH", "risk": "Shell remoto sin autenticacion", "severity": "CRITICAL"},
    1433: {"service": "MSSQL", "risk": "Base de datos SQL expuesta directamente", "severity": "HIGH"},
    1521: {"service": "Oracle DB", "risk": "Base de datos Oracle expuesta", "severity": "HIGH"},
    2049: {"service": "NFS", "risk": "Network File System - acceso a archivos", "severity": "HIGH"},
    3306: {"service": "MySQL", "risk": "Base de datos expuesta directamente", "severity": "HIGH"},
    3389: {"service": "RDP", "risk": "BlueKeep y vulnerabilidades criticas de RDP", "severity": "CRITICAL"},
    4444: {"service": "Metasploit/Backdoor", "risk": "Puerto tipico de backdoors y C2", "severity": "CRITICAL"},
    5432: {"service": "PostgreSQL", "risk": "Base de datos expuesta directamente", "severity": "HIGH"},
    5900: {"service": "VNC", "risk": "Acceso remoto grafico - autenticacion debil comun", "severity": "HIGH"},
    6379: {"service": "Redis", "risk": "Cache/BD sin autenticacion por defecto", "severity": "CRITICAL"},
    8080: {"service": "HTTP-Alt", "risk": "Servidor web alternativo - puede tener panel admin", "severity": "MEDIUM"},
    8443: {"service": "HTTPS-Alt", "risk": "HTTPS alternativo", "severity": "INFO"},
    9200: {"service": "Elasticsearch", "risk": "Sin autenticacion por defecto - fuga de datos", "severity": "CRITICAL"},
    27017: {"service": "MongoDB", "risk": "Sin autenticacion por defecto", "severity": "CRITICAL"},
}

SCAN_PROFILES: dict[str, str] = {
    "fast": NMAP_FAST_ARGS,
    "default": NMAP_DEFAULT_ARGS,
    "full": NMAP_FULL_ARGS,
    "vuln": NMAP_VULN_ARGS,
    "udp": NMAP_UDP_ARGS,
    "stealth": "-sS -sV --version-intensity 3 -T2",
    "comprehensive": f"{NMAP_FULL_ARGS} --script=vuln,exploit,auth",
}


class NmapScanner:
    """
    Potenciado nmap scanner with:
    - Multiple scan profiles
    - Automatic version vulnerability detection
    - High-risk port categorization
    - MITRE ATT&CK / NIST / CIS mapping
    """

    def __init__(self, target: str, profile: str = "default", verbose: bool = True):
        self.target = target
        self.profile = profile
        self.verbose = verbose
        self.nm = nmap.PortScanner()
        self.findings: list[dict] = []
        self.open_ports: list[int] = []
        self.services: dict = {}

    def _log(self, msg: str, level: str = "INFO"):
        colors = {"INFO": "\033[96m", "WARNING": "\033[93m", "ERROR": "\033[91m"}
        if self.verbose:
            print(f"{colors.get(level, '')}  [NMAP] {msg}\033[0m")

    def _finding(self, fid: str, title: str, severity: str, description: str,
                 category: str, evidence: str, port: int = 0,
                 remediation: list[str] | None = None) -> dict:
        tactic = MITRE_TACTICS.get(category, {})
        return {
            "id": fid,
            "module": "NmapScanner",
            "title": title,
            "severity": severity,
            "description": description,
            "evidence": evidence,
            "target": self.target,
            "port": port,
            "category": category,
            "mitre": tactic,
            "nist": NIST_CONTROLS.get(category, []),
            "cis": CIS_CONTROLS.get(category, []),
            "timestamp": datetime.datetime.now().isoformat(),
            "remediation": remediation or tactic.get("mitigations", []),
        }

    def scan(self) -> list[dict]:
        args = SCAN_PROFILES.get(self.profile, NMAP_DEFAULT_ARGS)
        self._log(f"Ejecutando: nmap {args} {self.target}")

        try:
            self.nm.scan(hosts=self.target, arguments=args, timeout=NMAP_TIMEOUT)
        except nmap.PortScannerError as e:
            self._log(f"Error en nmap: {e}", "ERROR")
            return self.findings
        except Exception as e:
            self._log(f"Error inesperado: {e}", "ERROR")
            return self.findings

        for host in self.nm.all_hosts():
            self._log(f"Host: {host} ({self.nm[host].hostname()}) - {self.nm[host].state()}")
            self._analyze_host(host)

        return self.findings

    def _analyze_host(self, host: str):
        host_data = self.nm[host]

        # OS detection
        if "osmatch" in host_data and host_data["osmatch"]:
            best_os = host_data["osmatch"][0]
            self.findings.append(
                self._finding(
                    f"NMAP-OS-{len(self.findings)+1:03d}",
                    "Sistema operativo detectado",
                    "INFO",
                    f"OS detectado: {best_os['name']} (accuracy: {best_os['accuracy']}%)",
                    "info_disclosure",
                    f"OS: {best_os['name']} {best_os['accuracy']}%",
                )
            )

        for proto in host_data.all_protocols():
            ports = sorted(host_data[proto].keys())
            for port in ports:
                port_data = host_data[proto][port]
                state = port_data["state"]

                if state != "open":
                    continue

                self.open_ports.append(port)
                service_name = port_data.get("name", "unknown")
                product = port_data.get("product", "")
                version = port_data.get("version", "")
                extra = port_data.get("extrainfo", "")

                service_str = f"{service_name}"
                if product:
                    service_str += f" ({product}"
                    if version:
                        service_str += f" {version}"
                    service_str += ")"

                self.services[port] = {
                    "protocol": proto,
                    "service": service_name,
                    "product": product,
                    "version": version,
                    "extra": extra,
                    "scripts": port_data.get("script", {}),
                }

                self._log(f"  Puerto {port}/{proto}: {state} - {service_str}")

                # Open port finding
                risk_info = HIGH_RISK_PORTS.get(port, {})
                port_severity = risk_info.get("severity", "INFO")
                port_risk = risk_info.get("risk", "Puerto abierto detectado")

                self.findings.append(
                    self._finding(
                        f"NMAP-PORT-{port}",
                        f"Puerto {port}/{proto} abierto - {service_name.upper()}",
                        port_severity,
                        f"{port_risk}. Servicio: {service_str}",
                        "open_port",
                        f"Port: {port}/{proto} State: {state} Service: {service_str}",
                        port,
                        ["Cerrar puertos no necesarios", "Implementar firewall con reglas de minimo privilegio",
                         "Usar VPN para acceso a servicios de administracion"],
                    )
                )

                # Version vulnerability check
                if product:
                    self._check_version_vuln(port, product, version)

                # Script output analysis
                scripts = port_data.get("script", {})
                if scripts:
                    self._analyze_scripts(port, scripts)

    def _check_version_vuln(self, port: int, product: str, version: str):
        product_lower = product.lower()
        for key, (min_safe, cve, cvss, severity) in VULNERABLE_VERSIONS.items():
            if key in product_lower:
                if version:
                    self.findings.append(
                        self._finding(
                            f"NMAP-VULN-{port}-{key.upper().replace(' ', '_')}",
                            f"Version potencialmente vulnerable: {product} {version}",
                            severity,
                            f"Producto '{product} {version}' en puerto {port} puede ser vulnerable. "
                            f"Referencia: {cve} (CVSS: {cvss}). "
                            f"Version minima segura conocida: {min_safe}",
                            "outdated_service",
                            f"Product: {product} Version: {version} CVE: {cve} CVSS: {cvss}",
                            port,
                            [f"Actualizar {product} a version {min_safe} o superior",
                             "Aplicar parches de seguridad inmediatamente",
                             "Implementar WAF como medida de mitigacion temporal"],
                        )
                    )
                    self._log(f"  [VULN] {product} {version} -> {cve} (CVSS {cvss})", "WARNING")

    def _analyze_scripts(self, port: int, scripts: dict):
        vuln_keywords = [
            "VULNERABLE", "CVE-", "exploit", "EXPLOITABLE",
            "authentication bypass", "default credentials",
        ]
        for script_name, output in scripts.items():
            output_str = str(output)
            for kw in vuln_keywords:
                if kw.lower() in output_str.lower():
                    self.findings.append(
                        self._finding(
                            f"NMAP-SCRIPT-{port}-{script_name[:20].upper()}",
                            f"Script NSE detecta vulnerabilidad: {script_name}",
                            "HIGH",
                            f"El script '{script_name}' reporta posible vulnerabilidad en puerto {port}",
                            "outdated_service",
                            f"Script: {script_name}\nOutput: {output_str[:500]}",
                            port,
                        )
                    )
                    self._log(f"  [SCRIPT-VULN] {script_name} en puerto {port}", "WARNING")
                    break
