"""
Report Generator — Produces structured HTML reports with remediation guidance
"""

from datetime import datetime


class ReportGenerator:
    SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    SEVERITY_COLORS = {
        "critical": "#ff2d55",
        "high": "#ff6b35",
        "medium": "#ffd700",
        "low": "#00b8ff",
    }

    def __init__(self, scan_data):
        self.scan = scan_data

    def generate_html(self):
        findings = sorted(
            self.scan.get("findings", []),
            key=lambda f: self.SEVERITY_ORDER.get(f.get("severity", "low"), 99)
        )
        total = len(findings)
        counts = {s: sum(1 for f in findings if f.get("severity") == s)
                  for s in ["critical", "high", "medium", "low"]}

        findings_html = ""
        for i, f in enumerate(findings, 1):
            color = self.SEVERITY_COLORS.get(f.get("severity", "low"), "#888")
            bypass_note = ""
            if f.get("bypass_used"):
                bypass_note = f'<span style="background:#1a1a2e;color:#888;padding:2px 8px;font-size:11px;border:1px solid #333;margin-left:8px">{f.get("bypass_technique","")}</span>'

            findings_html += f"""
            <tr>
              <td style="padding:12px;color:{color};font-weight:700;text-transform:uppercase;font-size:12px">{f.get('severity','')}</td>
              <td style="padding:12px">{f.get('type','')} {bypass_note}</td>
              <td style="padding:12px;font-family:monospace;font-size:12px;color:#888">{f.get('endpoint','')}</td>
              <td style="padding:12px;color:{color};font-weight:700">{f.get('cvss','')}</td>
              <td style="padding:12px;font-size:12px;color:#aaa">{f.get('remediation','')}</td>
            </tr>"""

        return f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8">
<title>VulnScan Report — {self.scan.get('id','')}</title>
<style>
  body {{ font-family: 'Courier New', monospace; background: #020408; color: #c8dde8; margin: 0; padding: 32px; }}
  h1 {{ color: #00ff88; font-size: 28px; margin-bottom: 4px; }}
  .meta {{ color: #3a6070; font-size: 13px; margin-bottom: 32px; }}
  .summary {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 32px; }}
  .sev-box {{ background: #0a1520; border: 1px solid #0d2535; padding: 20px; text-align: center; }}
  .sev-num {{ font-size: 36px; font-weight: 900; }}
  .sev-lbl {{ font-size: 11px; color: #3a6070; letter-spacing: 2px; text-transform: uppercase; }}
  table {{ width: 100%; border-collapse: collapse; }}
  th {{ text-align: left; padding: 10px 12px; font-size: 11px; color: #3a6070; border-bottom: 1px solid #0d2535; letter-spacing: 2px; text-transform: uppercase; }}
  tr:hover td {{ background: rgba(0,255,136,0.02); }}
  td {{ border-bottom: 1px solid #0a1520; vertical-align: top; }}
</style>
</head><body>
<h1>VULNSCAN // SECURITY REPORT</h1>
<div class="meta">
  Scan ID: {self.scan.get('id','')} &nbsp;|&nbsp;
  Target: {self.scan.get('target','')} &nbsp;|&nbsp;
  Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')} &nbsp;|&nbsp;
  Requests: {self.scan.get('requests_sent',0)} &nbsp;|&nbsp;
  WAF: {self.scan.get('waf_detected','None')}
</div>

<div class="summary">
  <div class="sev-box"><div class="sev-num" style="color:#ff2d55">{counts['critical']}</div><div class="sev-lbl">Critical</div></div>
  <div class="sev-box"><div class="sev-num" style="color:#ff6b35">{counts['high']}</div><div class="sev-lbl">High</div></div>
  <div class="sev-box"><div class="sev-num" style="color:#ffd700">{counts['medium']}</div><div class="sev-lbl">Medium</div></div>
  <div class="sev-box"><div class="sev-num" style="color:#00b8ff">{counts['low']}</div><div class="sev-lbl">Low</div></div>
</div>

<table>
  <thead><tr>
    <th>Severity</th><th>Vulnerability</th><th>Endpoint</th>
    <th>CVSS</th><th>Remediation</th>
  </tr></thead>
  <tbody>{findings_html}</tbody>
</table>
</body></html>"""
