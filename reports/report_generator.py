"""
ClaudeCiberControl - Report Generator
Generates Technical and Corporate reports in HTML, JSON, and TXT formats
"""

import json
import os
import datetime
from config.settings import TOOL_NAME, VERSION, COMPANY_NAME, REPORT_DISCLAIMER, REPORTS_DIR


SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
SEVERITY_HTML_COLORS = {
    "CRITICAL": "#dc2626", "HIGH": "#ea580c",
    "MEDIUM": "#ca8a04", "LOW": "#16a34a", "INFO": "#2563eb",
}

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{title}</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: 'Segoe UI', Arial, sans-serif; background: #0f172a; color: #e2e8f0; }}
  .header {{ background: linear-gradient(135deg, #1e3a5f 0%, #0f172a 100%);
             padding: 40px; border-bottom: 3px solid #3b82f6; }}
  .header h1 {{ color: #60a5fa; font-size: 2em; }}
  .header .meta {{ color: #94a3b8; margin-top: 10px; font-size: 0.9em; }}
  .container {{ max-width: 1200px; margin: 0 auto; padding: 30px; }}
  .summary-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
                   gap: 15px; margin: 30px 0; }}
  .summary-card {{ background: #1e293b; border-radius: 10px; padding: 20px; text-align: center;
                   border-left: 4px solid; }}
  .summary-card .count {{ font-size: 2.5em; font-weight: bold; }}
  .summary-card .label {{ color: #94a3b8; font-size: 0.85em; margin-top: 5px; }}
  .card-critical {{ border-color: #dc2626; }} .card-critical .count {{ color: #dc2626; }}
  .card-high {{ border-color: #ea580c; }} .card-high .count {{ color: #ea580c; }}
  .card-medium {{ border-color: #ca8a04; }} .card-medium .count {{ color: #ca8a04; }}
  .card-low {{ border-color: #16a34a; }} .card-low .count {{ color: #16a34a; }}
  .card-total {{ border-color: #3b82f6; }} .card-total .count {{ color: #3b82f6; }}
  .card-risk {{ border-color: #8b5cf6; }} .card-risk .count {{ color: #8b5cf6; font-size: 1.8em; }}
  .section-title {{ color: #60a5fa; font-size: 1.3em; margin: 30px 0 15px;
                    border-bottom: 1px solid #334155; padding-bottom: 8px; }}
  .finding {{ background: #1e293b; border-radius: 8px; margin: 12px 0; border-left: 5px solid; }}
  .finding-header {{ display: flex; justify-content: space-between; align-items: center;
                     padding: 15px 20px; }}
  .finding-body {{ padding: 15px 20px; border-top: 1px solid #334155; }}
  .badge {{ display: inline-block; padding: 3px 10px; border-radius: 20px;
            font-size: 0.75em; font-weight: bold; }}
  .finding-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 10px; margin-top: 10px; }}
  .finding-field {{ background: #0f172a; padding: 10px; border-radius: 6px; }}
  .finding-field .key {{ color: #64748b; font-size: 0.75em; text-transform: uppercase; }}
  .finding-field .val {{ color: #cbd5e1; margin-top: 4px; font-size: 0.85em; word-break: break-all; }}
  .evidence {{ background: #0f172a; padding: 10px; border-radius: 6px; margin-top: 10px;
               font-family: monospace; font-size: 0.8em; color: #94a3b8; white-space: pre-wrap; }}
  .remediation {{ background: #162032; border-left: 3px solid #16a34a;
                  padding: 10px 15px; margin-top: 10px; border-radius: 0 6px 6px 0; }}
  .remediation li {{ color: #86efac; margin: 4px 0; font-size: 0.85em; }}
  .metadata {{ background: #1e293b; border-radius: 8px; padding: 20px; margin: 20px 0; }}
  .metadata table {{ width: 100%; border-collapse: collapse; }}
  .metadata td {{ padding: 8px 12px; border-bottom: 1px solid #334155; font-size: 0.9em; }}
  .metadata td:first-child {{ color: #64748b; width: 200px; }}
  .disclaimer {{ background: #1e293b; border: 1px solid #334155; border-radius: 8px;
                 padding: 15px 20px; margin: 20px 0; color: #64748b; font-size: 0.8em; }}
  .progress-bar {{ background: #334155; border-radius: 10px; height: 8px; margin: 5px 0; }}
  .progress-fill {{ height: 100%; border-radius: 10px; }}
</style>
</head>
<body>
<div class="header">
  <h1>&#x1F6E1; {tool} Security Report</h1>
  <div class="meta">
    <strong>Objetivo:</strong> {target} &nbsp;|&nbsp;
    <strong>Fecha:</strong> {date} &nbsp;|&nbsp;
    <strong>Scan ID:</strong> {scan_id}
  </div>
</div>
<div class="container">
{summary_section}
{metadata_section}
{findings_section}
<div class="disclaimer"><strong>AVISO LEGAL:</strong> {disclaimer}</div>
<div style="text-align:center;color:#334155;padding:20px;font-size:0.8em">
  Generado por {tool} v{version} &mdash; {date}
</div>
</div>
</body>
</html>"""


def _severity_badge(severity: str) -> str:
    c = SEVERITY_HTML_COLORS.get(severity, "#64748b")
    return f'<span class="badge" style="background:{c}20;color:{c};border:1px solid {c}">{severity}</span>'


def _build_summary(stats: dict, metadata: dict) -> str:
    risk = metadata.get("risk_score", 0)
    risk_level = metadata.get("risk_level", "N/A")
    return f"""
<h2 class="section-title">&#x1F4CA; Resumen Ejecutivo</h2>
<div class="summary-grid">
  <div class="summary-card card-critical"><div class="count">{stats.get('critical',0)}</div><div class="label">CRITICAL</div></div>
  <div class="summary-card card-high"><div class="count">{stats.get('high',0)}</div><div class="label">HIGH</div></div>
  <div class="summary-card card-medium"><div class="count">{stats.get('medium',0)}</div><div class="label">MEDIUM</div></div>
  <div class="summary-card card-low"><div class="count">{stats.get('low',0)}</div><div class="label">LOW</div></div>
  <div class="summary-card card-total"><div class="count">{stats.get('total',0)}</div><div class="label">TOTAL</div></div>
  <div class="summary-card card-risk">
    <div class="count">{risk}% {risk_level}</div><div class="label">NIVEL DE RIESGO</div>
    <div class="progress-bar"><div class="progress-fill" style="width:{risk}%;background:#8b5cf6"></div></div>
  </div>
</div>"""


def _build_metadata(metadata: dict) -> str:
    rows = ""
    for key, label in [("ip", "IP"), ("open_ports", "Puertos Abiertos"),
                       ("risk_score", "Score de Riesgo"), ("risk_level", "Nivel")]:
        val = metadata.get(key, "N/A")
        if isinstance(val, list):
            val = ", ".join(str(v) for v in val) or "Ninguno"
        rows += f"<tr><td>{label}</td><td>{val}</td></tr>"
    whois = metadata.get("whois", {})
    if whois.get("registrar"):
        rows += f"<tr><td>Registrar</td><td>{whois['registrar']}</td></tr>"
    return f'<h2 class="section-title">&#x1F5A5; Informacion del Objetivo</h2><div class="metadata"><table>{rows}</table></div>'


def _build_findings(findings: list) -> str:
    html = '<h2 class="section-title">&#x1F50D; Hallazgos de Seguridad</h2>'
    current_sev = None
    for f in sorted(findings, key=lambda x: SEVERITY_ORDER.index(x.get("severity", "INFO"))
                    if x.get("severity", "INFO") in SEVERITY_ORDER else 99):
        sev = f.get("severity", "INFO")
        color = SEVERITY_HTML_COLORS.get(sev, "#64748b")
        if sev != current_sev:
            current_sev = sev
            html += f'<h3 style="color:{color};margin:25px 0 10px">── {sev} ──</h3>'
        mitre = f.get("mitre", {})
        nist = f.get("nist", [])
        cis = f.get("cis", [])
        remediation = f.get("remediation", [])
        rem_html = ""
        if remediation:
            items = "".join(f"<li>{r}</li>" for r in remediation)
            rem_html = f'<div class="remediation"><strong style="color:#86efac">Remediation:</strong><ul style="padding-left:15px;margin-top:5px">{items}</ul></div>'
        html += f"""
<div class="finding" style="border-color:{color}">
  <div class="finding-header">
    <span><strong style="color:{color}">{f.get('id','')}</strong> &nbsp; {f.get('title','')}</span>
    {_severity_badge(sev)}
  </div>
  <div class="finding-body">
    <p style="color:#cbd5e1;margin-bottom:10px">{f.get('description','')}</p>
    <div class="finding-grid">
      <div class="finding-field"><div class="key">Modulo</div><div class="val">{f.get('module','')}</div></div>
      <div class="finding-field"><div class="key">Objetivo</div><div class="val">{f.get('target','')}</div></div>
      {'<div class="finding-field"><div class="key">MITRE ATT&amp;CK</div><div class="val">' + str(mitre.get('tactic','')) + '<br><small>' + str(mitre.get('technique','')) + '</small></div></div>' if mitre.get('tactic') else ''}
      {'<div class="finding-field"><div class="key">NIST</div><div class="val">' + ' | '.join(nist) + '</div></div>' if nist else ''}
      {'<div class="finding-field"><div class="key">CIS Controls v8</div><div class="val">' + ' | '.join(cis) + '</div></div>' if cis else ''}
    </div>
    {'<div class="evidence">' + f.get('evidence','') + '</div>' if f.get('evidence') else ''}
    {rem_html}
  </div>
</div>"""
    return html


class ReportGenerator:
    def __init__(self, scan_result, verbose: bool = True):
        self.scan_result = scan_result
        self.verbose = verbose
        os.makedirs(REPORTS_DIR, exist_ok=True)

    def _log(self, msg: str):
        if self.verbose:
            print(f"\033[92m  [REPORT] {msg}\033[0m")

    def generate_all(self) -> dict:
        return {
            "json": self.generate_json(),
            "html_technical": self.generate_html_technical(),
            "html_corporate": self.generate_html_corporate(),
            "txt": self.generate_txt(),
        }

    def generate_json(self) -> str:
        path = os.path.join(REPORTS_DIR, f"report_{self.scan_result.scan_id}.json")
        with open(path, "w") as f:
            json.dump(self.scan_result.to_dict(), f, indent=2, default=str)
        self._log(f"JSON: {path}")
        return path

    def generate_html_technical(self) -> str:
        data = self.scan_result.to_dict()
        html = HTML_TEMPLATE.format(
            title=f"Reporte Tecnico - {data['target']}",
            tool=TOOL_NAME, version=VERSION, target=data["target"],
            date=datetime.datetime.now().strftime("%Y-%m-%d %H:%M"),
            scan_id=data["scan_id"],
            summary_section=_build_summary(data["statistics"], data["metadata"]),
            metadata_section=_build_metadata(data["metadata"]),
            findings_section=_build_findings(data["findings"]),
            disclaimer=REPORT_DISCLAIMER,
        )
        path = os.path.join(REPORTS_DIR, f"report_technical_{self.scan_result.scan_id}.html")
        with open(path, "w", encoding="utf-8") as f:
            f.write(html)
        self._log(f"HTML tecnico: {path}")
        return path

    def generate_html_corporate(self) -> str:
        data = self.scan_result.to_dict()
        stats = data["statistics"]
        metadata = data["metadata"]
        risk = metadata.get("risk_score", 0)
        risk_level = metadata.get("risk_level", "N/A")
        risk_color = "#dc2626" if risk >= 70 else "#ea580c" if risk >= 50 else "#ca8a04" if risk >= 25 else "#16a34a"
        exec_findings = [f for f in data["findings"] if f.get("severity") in ("CRITICAL", "HIGH")]
        exec_section = f"""
<h2 class="section-title">&#x1F4BC; Resumen Ejecutivo</h2>
<div class="metadata">
  <p style="color:#cbd5e1;margin-bottom:20px">
    Evaluacion de <strong style="color:#60a5fa">{data['target']}</strong> el {datetime.datetime.now().strftime('%d/%m/%Y')}.
    Total <strong style="color:#3b82f6">{stats['total']} hallazgos</strong>:
    <strong style="color:#dc2626">{stats['critical']} CRITICOS</strong> y
    <strong style="color:#ea580c">{stats['high']} ALTOS</strong>.
  </p>
  <div style="text-align:center;padding:20px">
    <div style="font-size:3em;font-weight:bold;color:{risk_color}">{risk}%</div>
    <div>Riesgo Global: <strong style="color:{risk_color}">{risk_level}</strong></div>
    <div class="progress-bar" style="max-width:400px;margin:10px auto;height:12px">
      <div class="progress-fill" style="width:{risk}%;background:{risk_color}"></div>
    </div>
  </div>
</div>
<h2 class="section-title">&#x26A0; Hallazgos Criticos y Altos</h2>"""
        for f in exec_findings:
            sev = f.get("severity", "INFO")
            color = SEVERITY_HTML_COLORS.get(sev, "#64748b")
            mitre = f.get("mitre", {})
            items = "".join(f"<li>{r}</li>" for r in f.get("remediation", [])[:3])
            exec_section += f"""
<div class="finding" style="border-color:{color}">
  <div class="finding-header"><span>{_severity_badge(sev)} &nbsp; <strong>{f.get('title','')}</strong></span></div>
  <div class="finding-body">
    <p style="color:#cbd5e1;margin-bottom:8px">{f.get('description','')}</p>
    <div class="finding-grid">
      <div class="finding-field"><div class="key">MITRE</div><div class="val">{mitre.get('tactic','N/A')}</div></div>
      <div class="finding-field"><div class="key">Accion Recomendada</div><div class="val"><ul style="padding-left:15px">{items}</ul></div></div>
    </div>
  </div>
</div>"""
        html = HTML_TEMPLATE.format(
            title=f"Reporte Corporativo - {data['target']}",
            tool=TOOL_NAME, version=VERSION, target=data["target"],
            date=datetime.datetime.now().strftime("%Y-%m-%d %H:%M"),
            scan_id=data["scan_id"],
            summary_section=_build_summary(stats, metadata),
            metadata_section=exec_section,
            findings_section="",
            disclaimer=REPORT_DISCLAIMER,
        )
        path = os.path.join(REPORTS_DIR, f"report_corporate_{self.scan_result.scan_id}.html")
        with open(path, "w", encoding="utf-8") as f:
            f.write(html)
        self._log(f"HTML corporativo: {path}")
        return path

    def generate_txt(self) -> str:
        data = self.scan_result.to_dict()
        lines = [
            "=" * 70,
            f"  {TOOL_NAME} - REPORTE DE SEGURIDAD",
            "=" * 70,
            f"  Objetivo : {data['target']}",
            f"  Scan ID  : {data['scan_id']}",
            f"  Inicio   : {data['start_time']}",
            f"  Fin      : {data['end_time']}",
            f"  Riesgo   : {data['metadata'].get('risk_score','N/A')}% - {data['metadata'].get('risk_level','N/A')}",
            "=" * 70, "",
            "RESUMEN:",
            f"  Total    : {data['statistics']['total']}",
            f"  CRITICAL : {data['statistics']['critical']}",
            f"  HIGH     : {data['statistics']['high']}",
            f"  MEDIUM   : {data['statistics']['medium']}",
            f"  LOW      : {data['statistics']['low']}",
            "", "HALLAZGOS:", "-" * 70,
        ]
        for f in sorted(data["findings"],
                        key=lambda x: SEVERITY_ORDER.index(x.get("severity","INFO"))
                        if x.get("severity","INFO") in SEVERITY_ORDER else 99):
            lines += [
                f"[{f.get('severity','?')}] {f.get('id','')} - {f.get('title','')}",
                f"  {f.get('description','')}",
                f"  MITRE: {f.get('mitre',{}).get('tactic','N/A')}",
                f"  NIST: {', '.join(f.get('nist',[]))}", "",
            ]
        lines += ["=" * 70, f"  {REPORT_DISCLAIMER}", "=" * 70]
        path = os.path.join(REPORTS_DIR, f"report_{self.scan_result.scan_id}.txt")
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
        self._log(f"TXT: {path}")
        return path
