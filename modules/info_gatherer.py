"""
ClaudeCiberControl - Information Gathering Module
MITRE ATT&CK: TA0043 Reconnaissance - T1590/T1592/T1596
"""

import socket
import re
import datetime
from typing import Optional
import dns.resolver
import whois
import requests
from config.settings import HTTP_TIMEOUT, USER_AGENT, MITRE_TACTICS, NIST_CONTROLS, CIS_CONTROLS


class InfoGatherer:
    """
    Passive/active information gathering:
    DNS, WHOIS, reverse DNS, HTTP headers, robots.txt, sitemap
    """

    def __init__(self, target: str, verbose: bool = True):
        self.target = target
        self.verbose = verbose
        self.host = self._extract_host(target)
        self.findings: list[dict] = []

    def _extract_host(self, target: str) -> str:
        target = target.strip()
        for prefix in ("https://", "http://"):
            if target.startswith(prefix):
                target = target[len(prefix):]
        return target.split("/")[0].split(":")[0]

    def _log(self, msg: str):
        if self.verbose:
            print(f"\033[96m  [INFO] {msg}\033[0m")

    def _finding(self, title: str, severity: str, description: str,
                 category: str = "info_disclosure", evidence: str = "") -> dict:
        tactic = MITRE_TACTICS.get(category, {})
        return {
            "id": f"INFO-{len(self.findings)+1:03d}",
            "module": "InfoGatherer",
            "title": title,
            "severity": severity,
            "description": description,
            "evidence": evidence,
            "target": self.host,
            "category": category,
            "mitre": tactic,
            "nist": NIST_CONTROLS.get(category, []),
            "cis": CIS_CONTROLS.get(category, []),
            "timestamp": datetime.datetime.now().isoformat(),
            "remediation": tactic.get("mitigations", []),
        }

    def gather(self) -> dict:
        self._log(f"Recopilando informacion de: {self.host}")
        result: dict = {"findings": [], "dns": {}, "whois": {}, "ip": ""}

        # IP resolution
        result["ip"] = self._resolve_ip()

        # DNS records
        result["dns"] = self._get_dns_records()

        # WHOIS
        result["whois"] = self._get_whois()

        # HTTP banner
        self._check_http_banner()

        result["findings"] = self.findings
        return result

    def _resolve_ip(self) -> str:
        try:
            ip = socket.gethostbyname(self.host)
            self._log(f"IP resuelta: {ip}")
            self.findings.append(
                self._finding(
                    "Resolucion DNS exitosa",
                    "INFO",
                    f"El host {self.host} resuelve a la IP {ip}",
                    "info_disclosure",
                    f"IP: {ip}",
                )
            )
            return ip
        except socket.gaierror as e:
            self._log(f"No se pudo resolver {self.host}: {e}")
            return ""

    def _get_dns_records(self) -> dict:
        records: dict = {}
        record_types = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME"]
        for rtype in record_types:
            try:
                answers = dns.resolver.resolve(self.host, rtype, lifetime=5)
                records[rtype] = [str(r) for r in answers]
                self._log(f"DNS {rtype}: {records[rtype]}")
            except Exception:
                pass

        if "TXT" in records:
            for txt in records["TXT"]:
                if "v=spf" not in txt.lower() and "v=dkim" not in txt.lower():
                    self.findings.append(
                        self._finding(
                            "Registro TXT con informacion sensible potencial",
                            "LOW",
                            f"Registro TXT expuesto: {txt}",
                            "info_disclosure",
                            txt,
                        )
                    )
        return records

    def _get_whois(self) -> dict:
        try:
            w = whois.whois(self.host)
            data = {
                "registrar": str(w.registrar or ""),
                "creation_date": str(w.creation_date or ""),
                "expiration_date": str(w.expiration_date or ""),
                "name_servers": w.name_servers or [],
            }
            self._log(f"WHOIS registrar: {data['registrar']}")
            return data
        except Exception:
            return {}

    def _check_http_banner(self):
        for scheme in ("https", "http"):
            url = f"{scheme}://{self.host}"
            try:
                resp = requests.get(
                    url,
                    timeout=HTTP_TIMEOUT,
                    headers={"User-Agent": USER_AGENT},
                    verify=False,
                    allow_redirects=True,
                )
                server = resp.headers.get("Server", "")
                x_powered = resp.headers.get("X-Powered-By", "")

                if server:
                    self.findings.append(
                        self._finding(
                            "Banner del servidor expuesto",
                            "LOW",
                            f"El servidor revela informacion de tecnologia en el header 'Server': {server}",
                            "info_disclosure",
                            f"Server: {server}",
                        )
                    )
                    self._log(f"Server header: {server}")

                if x_powered:
                    self.findings.append(
                        self._finding(
                            "Header X-Powered-By expuesto",
                            "LOW",
                            f"El header X-Powered-By revela tecnologia backend: {x_powered}",
                            "info_disclosure",
                            f"X-Powered-By: {x_powered}",
                        )
                    )
                break
            except Exception:
                continue
