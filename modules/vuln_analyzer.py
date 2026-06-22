"""
ClaudeCiberControl - Vulnerability Correlator & Analyzer
Cross-references findings with MITRE ATT&CK, assigns risk scores,
and generates attack chain analysis
"""

import datetime
from config.settings import CVSS_CRITICAL, CVSS_HIGH, CVSS_MEDIUM, MITRE_TACTICS, NIST_CONTROLS, CIS_CONTROLS


SEVERITY_SCORE = {"CRITICAL": 10, "HIGH": 7, "MEDIUM": 4, "LOW": 1, "INFO": 0}

# Risk multipliers when services are combined
RISK_CHAINS = [
    {
        "name": "Base de datos expuesta directamente",
        "conditions": lambda ports: any(p in ports for p in [3306, 5432, 1433, 1521, 27017, 6379, 9200]),
        "severity": "CRITICAL",
        "description": "Se detectan puertos de bases de datos accesibles directamente desde Internet. "
                       "Esto permite ataques de fuerza bruta directos, explotacion de vulnerabilidades "
                       "del motor de BD y posible exfiltracion masiva de datos.",
        "mitre": "TA0006 - Credential Access / TA0009 - Collection",
        "technique": "T1078 - Valid Accounts / T1213 - Data from Information Repositories",
    },
    {
        "name": "Exposicion de servicios de administracion remota",
        "conditions": lambda ports: sum(1 for p in [22, 3389, 5900, 23] if p in ports) >= 2,
        "severity": "HIGH",
        "description": "Multiples servicios de administracion remota expuestos (SSH, RDP, VNC, Telnet). "
                       "Incrementa la superficie de ataque para acceso no autorizado.",
        "mitre": "TA0008 - Lateral Movement",
        "technique": "T1021 - Remote Services",
    },
    {
        "name": "Stack SMB vulnerable (EternalBlue potencial)",
        "conditions": lambda ports: 445 in ports,
        "severity": "CRITICAL",
        "description": "Puerto SMB 445 expuesto. Vector critico de los exploits EternalBlue (MS17-010), "
                       "PrintNightmare y otras vulnerabilidades criticas de Windows.",
        "mitre": "TA0001 - Initial Access / TA0008 - Lateral Movement",
        "technique": "T1210 - Exploitation of Remote Services",
    },
    {
        "name": "Protocolo Telnet inseguro activo",
        "conditions": lambda ports: 23 in ports,
        "severity": "CRITICAL",
        "description": "Telnet transmite credenciales y datos en texto plano. "
                       "Cualquier atacante en la red puede capturar sesiones activas.",
        "mitre": "TA0006 - Credential Access",
        "technique": "T1557 - Adversary-in-the-Middle",
    },
    {
        "name": "FTP sin cifrar activo",
        "conditions": lambda ports: 21 in ports and 990 not in ports,
        "severity": "HIGH",
        "description": "FTP estandar (sin cifrar) esta activo. Las credenciales y datos "
                       "transferidos son visibles en texto plano en la red.",
        "mitre": "TA0006 - Credential Access",
        "technique": "T1557 - Adversary-in-the-Middle",
    },
    {
        "name": "SNMP con community string publica",
        "conditions": lambda ports: 161 in ports,
        "severity": "HIGH",
        "description": "SNMP expuesto. Community strings por defecto (public/private) permiten "
                       "enumeracion completa del sistema y configuraciones de red.",
        "mitre": "TA0043 - Reconnaissance",
        "technique": "T1046 - Network Service Discovery",
    },
]


class VulnAnalyzer:
    """
    Post-scan vulnerability correlation and risk scoring.
    Identifies attack chains and provides executive risk summary.
    """

    def __init__(self, scan_result, verbose: bool = True):
        self.scan_result = scan_result
        self.verbose = verbose
        self.findings: list[dict] = []

    def _log(self, msg: str, level: str = "INFO"):
        colors = {"INFO": "\033[96m", "WARNING": "\033[93m", "CRITICAL": "\033[91m"}
        if self.verbose:
            print(f"{colors.get(level, '')}  [VULN] {msg}\033[0m")

    def _finding(self, fid: str, title: str, severity: str, description: str,
                 mitre: str, technique: str, remediation: list[str]) -> dict:
        return {
            "id": fid,
            "module": "VulnAnalyzer",
            "title": title,
            "severity": severity,
            "description": description,
            "evidence": f"Correlacion basada en puertos abiertos: {self.scan_result.metadata.get('open_ports', [])}",
            "target": self.scan_result.target,
            "category": "attack_chain",
            "mitre": {
                "tactic": mitre,
                "technique": technique,
                "mitigations": remediation,
            },
            "nist": NIST_CONTROLS.get("open_port", []),
            "cis": ["CIS-4: Secure Configuration", "CIS-12: Network Infrastructure Management"],
            "timestamp": datetime.datetime.now().isoformat(),
            "remediation": remediation,
        }

    def analyze(self) -> list[dict]:
        open_ports = self.scan_result.metadata.get("open_ports", [])

        # Attack chain detection
        for chain in RISK_CHAINS:
            if chain["conditions"](open_ports):
                self._log(f"Cadena de ataque detectada: {chain['name']}", "WARNING")
                self.findings.append(
                    self._finding(
                        f"CHAIN-{chain['name'][:20].upper().replace(' ', '_')}",
                        f"[CADENA DE ATAQUE] {chain['name']}",
                        chain["severity"],
                        chain["description"],
                        chain["mitre"],
                        chain["technique"],
                        ["Reducir superficie de ataque cerrando puertos no necesarios",
                         "Implementar segmentacion de red y Zero Trust Architecture",
                         "Aplicar CIS Benchmark correspondiente al sistema operativo"],
                    )
                )

        # Risk score calculation
        self._calculate_risk_score()

        return self.findings

    def _calculate_risk_score(self):
        all_findings = self.scan_result.findings + self.findings
        total_score = sum(SEVERITY_SCORE.get(f.get("severity", "INFO"), 0) for f in all_findings)
        max_score = len(all_findings) * 10 if all_findings else 1
        risk_pct = min(100, (total_score / max_score) * 100)

        if risk_pct >= 70:
            risk_level = "CRITICO"
        elif risk_pct >= 50:
            risk_level = "ALTO"
        elif risk_pct >= 25:
            risk_level = "MEDIO"
        else:
            risk_level = "BAJO"

        self.scan_result.metadata["risk_score"] = round(risk_pct, 1)
        self.scan_result.metadata["risk_level"] = risk_level
        self._log(f"Puntuacion de riesgo calculada: {risk_pct:.1f}% - Nivel: {risk_level}")
