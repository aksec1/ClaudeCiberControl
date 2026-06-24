"""
ClaudeCiberControl - Configuration Settings
Aligned with MITRE ATT&CK, NIST SP 800-115, CIS Controls v8
"""

import os

VERSION = "1.0.0"
TOOL_NAME = "ClaudeCiberControl"
AUTHOR = "Security Team"

OUTPUT_DIR = os.environ.get("CCC_OUTPUT_DIR", "output").rsplit("/", 1)[0] if "/" in os.environ.get("CCC_OUTPUT_DIR", "") else "output"
REPORTS_DIR = os.environ.get("CCC_OUTPUT_DIR", "output/reports")
LOGS_DIR = os.path.join(OUTPUT_DIR, "logs")

NMAP_DEFAULT_ARGS = "-sV -sC --version-intensity 5 -O"
NMAP_FAST_ARGS = "-F -sV --version-intensity 3"
NMAP_FULL_ARGS = "-sV -sC -A -O -p- --version-intensity 9"
NMAP_UDP_ARGS = "-sU --top-ports 200"
NMAP_VULN_ARGS = "-sV --script=vuln,exploit,auth,default"
NMAP_TIMEOUT = int(os.environ.get("CCC_NMAP_TIMEOUT", "300"))

HTTP_TIMEOUT = int(os.environ.get("CCC_HTTP_TIMEOUT", "10"))
USER_AGENT = os.environ.get("CCC_USER_AGENT", "ClaudeCiberControl/1.0 Security Scanner")
FOLLOW_REDIRECTS = True
MAX_REDIRECTS = 5
COMMON_PORTS = [80, 443, 8080, 8443, 8000, 8888, 3000, 5000]

CVSS_CRITICAL = 9.0
CVSS_HIGH = 7.0
CVSS_MEDIUM = 4.0
CVSS_LOW = 0.1

MITRE_TACTICS = {
    "open_port": {
        "tactic": "TA0043 - Reconnaissance",
        "technique": "T1046 - Network Service Discovery",
        "mitigations": ["M1030 - Network Segmentation", "M1031 - Network Intrusion Prevention"],
    },
    "outdated_service": {
        "tactic": "TA0001 - Initial Access",
        "technique": "T1190 - Exploit Public-Facing Application",
        "mitigations": ["M1051 - Update Software", "M1016 - Vulnerability Scanning"],
    },
    "default_credentials": {
        "tactic": "TA0006 - Credential Access",
        "technique": "T1078 - Valid Accounts",
        "mitigations": ["M1027 - Password Policies", "M1036 - Account Use Policies"],
    },
    "weak_ssl": {
        "tactic": "TA0009 - Collection",
        "technique": "T1557 - Adversary-in-the-Middle",
        "mitigations": ["M1041 - Encrypt Sensitive Information", "M1054 - Software Configuration"],
    },
    "missing_security_headers": {
        "tactic": "TA0001 - Initial Access",
        "technique": "T1190 - Exploit Public-Facing Application",
        "mitigations": ["M1021 - Restrict Web-Based Content", "M1054 - Software Configuration"],
    },
    "directory_listing": {
        "tactic": "TA0043 - Reconnaissance",
        "technique": "T1083 - File and Directory Discovery",
        "mitigations": ["M1022 - Restrict File and Directory Permissions"],
    },
    "info_disclosure": {
        "tactic": "TA0043 - Reconnaissance",
        "technique": "T1592 - Gather Victim Host Information",
        "mitigations": ["M1054 - Software Configuration", "M1013 - Application Developer Guidance"],
    },
}

NIST_CONTROLS = {
    "open_port": ["CM-7 - Least Functionality", "SC-7 - Boundary Protection"],
    "outdated_service": ["SI-2 - Flaw Remediation", "RA-5 - Vulnerability Monitoring"],
    "weak_ssl": ["SC-8 - Transmission Confidentiality", "SC-17 - PKI Certificates"],
    "missing_security_headers": ["SI-10 - Information Input Validation", "SC-28 - Protection at Rest"],
    "info_disclosure": ["SI-12 - Information Management", "AC-3 - Access Enforcement"],
    "default_credentials": ["IA-5 - Authenticator Management", "AC-2 - Account Management"],
}

CIS_CONTROLS = {
    "open_port": ["CIS-12: Network Infrastructure Management", "CIS-4: Secure Configuration"],
    "outdated_service": ["CIS-7: Continuous Vulnerability Management", "CIS-2: Inventory of Software Assets"],
    "weak_ssl": ["CIS-3: Data Protection", "CIS-4: Secure Configuration"],
    "missing_security_headers": ["CIS-4: Secure Configuration", "CIS-16: Application Software Security"],
    "info_disclosure": ["CIS-3: Data Protection", "CIS-16: Application Software Security"],
    "default_credentials": ["CIS-5: Account Management", "CIS-4: Secure Configuration"],
}

SEVERITY_COLORS = {
    "CRITICAL": "\033[91m",
    "HIGH": "\033[93m",
    "MEDIUM": "\033[94m",
    "LOW": "\033[92m",
    "INFO": "\033[96m",
    "RESET": "\033[0m",
}

REPORT_FORMATS = ["html", "json", "txt"]
COMPANY_NAME = os.environ.get("CCC_COMPANY_NAME", "ClaudeCiberControl Security")
REPORT_DISCLAIMER = (
    "Este reporte fue generado con fines de evaluacion de seguridad autorizada. "
    "La informacion contenida es confidencial y de uso exclusivo del destinatario."
)
