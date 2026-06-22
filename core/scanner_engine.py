"""
ClaudeCiberControl - Scanner Engine Core
Orchestrates all scanning modules and aggregates findings
"""

import json
import os
import datetime
from typing import Optional
from config.settings import OUTPUT_DIR, REPORTS_DIR, LOGS_DIR


class ScanResult:
    """Container for all findings from a single scan session."""

    def __init__(self, target: str):
        self.target = target
        self.scan_id = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        self.start_time = datetime.datetime.now().isoformat()
        self.end_time: Optional[str] = None
        self.findings: list[dict] = []
        self.metadata: dict = {}
        self.statistics: dict = {
            "total": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
        }

    def add_finding(self, finding: dict):
        self.findings.append(finding)
        sev = finding.get("severity", "INFO").upper()
        self.statistics["total"] += 1
        if sev in self.statistics:
            self.statistics[sev.lower()] += 1

    def finalize(self):
        self.end_time = datetime.datetime.now().isoformat()

    def to_dict(self) -> dict:
        return {
            "scan_id": self.scan_id,
            "target": self.target,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "metadata": self.metadata,
            "statistics": self.statistics,
            "findings": self.findings,
        }

    def save_json(self) -> str:
        os.makedirs(REPORTS_DIR, exist_ok=True)
        path = os.path.join(REPORTS_DIR, f"scan_{self.scan_id}.json")
        with open(path, "w") as f:
            json.dump(self.to_dict(), f, indent=2, default=str)
        return path


class ScannerEngine:
    """
    Main scanning orchestrator.
    Runs nmap, web, and vulnerability modules then aggregates results.
    """

    def __init__(self, target: str, scan_profile: str = "default", verbose: bool = True):
        self.target = target
        self.scan_profile = scan_profile
        self.verbose = verbose
        self.result = ScanResult(target)
        self._ensure_dirs()

    def _ensure_dirs(self):
        for d in [OUTPUT_DIR, REPORTS_DIR, LOGS_DIR]:
            os.makedirs(d, exist_ok=True)

    def _log(self, message: str, level: str = "INFO"):
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        colors = {
            "INFO": "\033[96m",
            "SUCCESS": "\033[92m",
            "WARNING": "\033[93m",
            "ERROR": "\033[91m",
            "SECTION": "\033[95m",
        }
        reset = "\033[0m"
        color = colors.get(level, "")
        if self.verbose:
            print(f"{color}[{timestamp}] [{level}] {message}{reset}")

    def run_full_scan(self) -> ScanResult:
        """Execute all scan modules in sequence."""
        from modules.nmap_scanner import NmapScanner
        from modules.web_scanner import WebScanner
        from modules.vuln_analyzer import VulnAnalyzer
        from modules.info_gatherer import InfoGatherer

        self._log(f"{'='*60}", "SECTION")
        self._log(f"  ClaudeCiberControl - Iniciando escaneo completo", "SECTION")
        self._log(f"  Objetivo: {self.target}", "SECTION")
        self._log(f"  Perfil: {self.scan_profile}", "SECTION")
        self._log(f"{'='*60}", "SECTION")

        # 1. Information Gathering
        self._log("FASE 1: Recopilacion de informacion", "SECTION")
        info = InfoGatherer(self.target, self.verbose)
        info_data = info.gather()
        self.result.metadata.update(info_data)
        for f in info_data.get("findings", []):
            self.result.add_finding(f)

        # 2. Nmap Port Scan
        self._log("FASE 2: Escaneo de puertos con Nmap", "SECTION")
        nmap = NmapScanner(self.target, self.scan_profile, self.verbose)
        nmap_findings = nmap.scan()
        for f in nmap_findings:
            self.result.add_finding(f)
        self.result.metadata["open_ports"] = nmap.open_ports
        self.result.metadata["services"] = nmap.services

        # 3. Web Scanner
        self._log("FASE 3: Analisis de aplicaciones web", "SECTION")
        web = WebScanner(self.target, self.verbose)
        web_findings = web.scan()
        for f in web_findings:
            self.result.add_finding(f)

        # 4. Vulnerability Analysis
        self._log("FASE 4: Correlacion de vulnerabilidades", "SECTION")
        vuln = VulnAnalyzer(self.result, self.verbose)
        vuln_findings = vuln.analyze()
        for f in vuln_findings:
            self.result.add_finding(f)

        self.result.finalize()
        self._log(f"{'='*60}", "SECTION")
        self._log(f"  Escaneo completado - {self.result.statistics['total']} hallazgos", "SUCCESS")
        self._log(f"  CRITICAL: {self.result.statistics['critical']}  HIGH: {self.result.statistics['high']}  MEDIUM: {self.result.statistics['medium']}  LOW: {self.result.statistics['low']}", "WARNING")
        self._log(f"{'='*60}", "SECTION")

        return self.result
