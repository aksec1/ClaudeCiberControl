#!/usr/bin/env python3
"""
╔═══════════════════════════════════════════════════════════════╗
║          ClaudeCiberControl - Security Scanner Suite          ║
║  Web Scanner + Nmap Potenciado + Vulnerability Analysis       ║
║  Frameworks: MITRE ATT&CK | NIST SP 800-115 | CIS Controls v8║
╚═══════════════════════════════════════════════════════════════╝
"""

import argparse
import sys
import os


BANNER = """
\033[94m╔═══════════════════════════════════════════════════════════════╗\033[0m
\033[94m║\033[96m       ██████╗██╗      █████╗ ██╗   ██╗██████╗ ███████╗        \033[94m║\033[0m
\033[94m║\033[96m      ██╔════╝██║     ██╔══██╗██║   ██║██╔══██╗██╔════╝        \033[94m║\033[0m
\033[94m║\033[96m      ██║     ██║     ███████║██║   ██║██║  ██║█████╗          \033[94m║\033[0m
\033[94m║\033[96m      ██║     ██║     ██╔══██║██║   ██║██║  ██║██╔══╝          \033[94m║\033[0m
\033[94m║\033[96m      ╚██████╗███████╗██║  ██║╚██████╔╝██████╔╝███████╗        \033[94m║\033[0m
\033[94m║\033[96m       ╚═════╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚══════╝       \033[94m║\033[0m
\033[94m║\033[0m                                                               \033[94m║\033[0m
\033[94m║\033[93m         CiberControl Security Scanner v1.0                    \033[94m║\033[0m
\033[94m║\033[92m   MITRE ATT&CK | NIST SP 800-115 | CIS Controls v8            \033[94m║\033[0m
\033[94m╚═══════════════════════════════════════════════════════════════╝\033[0m
"""

PROFILES_HELP = """
Perfiles de escaneo disponibles:
  fast           Escaneo rapido (top 100 puertos, -F)
  default        Escaneo balanceado con deteccion de versiones y scripts NSE
  full           Escaneo completo todos los puertos (-p-) con OS detection
  vuln           Scripts de vulnerabilidades NSE (vuln, exploit, auth)
  stealth        Escaneo sigiloso SYN scan, baja velocidad (-T2)
  udp            Escaneo UDP top 200 puertos
  comprehensive  Full scan + scripts vuln/exploit (mas lento, mas completo)
"""


def parse_args():
    parser = argparse.ArgumentParser(
        description="ClaudeCiberControl - Security Scanner Suite",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=PROFILES_HELP,
    )
    parser.add_argument(
        "target",
        nargs="?",
        help="IP, dominio o URL objetivo (ej: 192.168.1.1, example.com, https://example.com)",
    )
    parser.add_argument(
        "-p", "--profile",
        default="default",
        choices=["fast", "default", "full", "vuln", "stealth", "udp", "comprehensive"],
        help="Perfil de escaneo nmap (default: default)",
    )
    parser.add_argument(
        "--no-web",
        action="store_true",
        help="Omitir escaneo web (solo nmap + info gathering)",
    )
    parser.add_argument(
        "--no-report",
        action="store_true",
        help="No generar reportes al finalizar",
    )
    parser.add_argument(
        "--report-only-json",
        action="store_true",
        help="Generar solo reporte JSON (mas rapido)",
    )
    parser.add_argument(
        "-o", "--output",
        default="output/reports",
        help="Directorio de salida para reportes (default: output/reports)",
    )
    parser.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="Modo silencioso (menos output en consola)",
    )
    parser.add_argument(
        "--list-profiles",
        action="store_true",
        help="Listar perfiles de escaneo disponibles",
    )
    parser.add_argument(
        "--demo",
        action="store_true",
        help="Ejecutar demo con objetivo de prueba (scanme.nmap.org)",
    )
    return parser.parse_args()


def validate_target(target: str) -> bool:
    import re
    if not target:
        return False
    clean = target.strip()
    for prefix in ("https://", "http://"):
        if clean.startswith(prefix):
            clean = clean[len(prefix):]
    clean = clean.split("/")[0].split(":")[0]
    # IP pattern
    ip_pattern = r"^(\d{1,3}\.){3}\d{1,3}(/\d{1,2})?$"
    # Domain pattern
    domain_pattern = r"^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
    # Localhost
    if clean in ("localhost", "127.0.0.1") or clean.startswith("192.168.") or clean.startswith("10."):
        return True
    return bool(re.match(ip_pattern, clean) or re.match(domain_pattern, clean))


def run_scan(target: str, profile: str, verbose: bool, no_web: bool) -> "ScanResult":
    from core.scanner_engine import ScannerEngine
    engine = ScannerEngine(target, profile, verbose)

    if no_web:
        # Run partial scan without web module
        from modules.info_gatherer import InfoGatherer
        from modules.nmap_scanner import NmapScanner
        from modules.vuln_analyzer import VulnAnalyzer

        info = InfoGatherer(target, verbose)
        info_data = info.gather()
        engine.result.metadata.update(info_data)
        for f in info_data.get("findings", []):
            engine.result.add_finding(f)

        nmap = NmapScanner(target, profile, verbose)
        for f in nmap.scan():
            engine.result.add_finding(f)
        engine.result.metadata["open_ports"] = nmap.open_ports
        engine.result.metadata["services"] = nmap.services

        vuln = VulnAnalyzer(engine.result, verbose)
        for f in vuln.analyze():
            engine.result.add_finding(f)

        engine.result.finalize()
        return engine.result
    else:
        return engine.run_full_scan()


def print_summary(result):
    stats = result.statistics
    meta = result.metadata

    print(f"\n\033[95m{'='*60}\033[0m")
    print(f"\033[95m  RESUMEN DE HALLAZGOS\033[0m")
    print(f"\033[95m{'='*60}\033[0m")
    print(f"  Objetivo  : \033[96m{result.target}\033[0m")
    print(f"  Riesgo    : \033[93m{meta.get('risk_score', 'N/A')}% - {meta.get('risk_level', 'N/A')}\033[0m")
    print(f"  IP        : \033[96m{meta.get('ip', 'N/A')}\033[0m")
    print(f"  Puertos   : \033[96m{meta.get('open_ports', [])}\033[0m")
    print()
    colors = {
        "CRITICAL": "\033[91m", "HIGH": "\033[93m",
        "MEDIUM": "\033[94m", "LOW": "\033[92m", "INFO": "\033[96m",
    }
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        count = stats.get(sev.lower(), 0)
        if count > 0:
            bar = "█" * min(count, 40)
            print(f"  {colors[sev]}{sev:10s} {count:4d}  {bar}\033[0m")
    print(f"\033[95m{'='*60}\033[0m\n")


def main():
    print(BANNER)
    args = parse_args()

    if args.list_profiles:
        print(PROFILES_HELP)
        sys.exit(0)

    if args.demo:
        args.target = "scanme.nmap.org"
        print(f"\033[93m[DEMO] Usando objetivo de prueba: {args.target}\033[0m\n")

    if not args.target:
        print("\033[91m[ERROR] Debe especificar un objetivo. Uso: python3 main.py <target>\033[0m")
        print("Ejemplo: python3 main.py 192.168.1.1")
        print("Ejemplo: python3 main.py example.com --profile full")
        print("Ejemplo: python3 main.py https://example.com")
        print("\nUse --demo para ejecutar con objetivo de prueba")
        print("Use --list-profiles para ver perfiles disponibles")
        sys.exit(1)

    if not validate_target(args.target):
        print(f"\033[91m[ERROR] Objetivo invalido: {args.target}\033[0m")
        sys.exit(1)

    verbose = not args.quiet

    try:
        result = run_scan(args.target, args.profile, verbose, args.no_web)
    except KeyboardInterrupt:
        print("\n\033[93m[!] Escaneo interrumpido por el usuario\033[0m")
        sys.exit(0)
    except Exception as e:
        print(f"\033[91m[ERROR] Error durante el escaneo: {e}\033[0m")
        if verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)

    print_summary(result)

    if not args.no_report:
        from reports.report_generator import ReportGenerator
        print("\033[96m[*] Generando reportes...\033[0m")
        reporter = ReportGenerator(result, verbose)

        if args.report_only_json:
            path = reporter.generate_json()
            print(f"\033[92m[+] JSON: {path}\033[0m")
        else:
            paths = reporter.generate_all()
            print()
            print("\033[92m[+] Reportes generados:\033[0m")
            for fmt, path in paths.items():
                print(f"    \033[96m{fmt:20s}\033[0m: {path}")

    print(f"\n\033[92m[✓] Escaneo completado exitosamente\033[0m\n")


if __name__ == "__main__":
    main()
