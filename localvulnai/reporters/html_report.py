from typing import List
from pathlib import Path
from datetime import datetime, timezone
from localvulnai.models.finding import Finding
from localvulnai.utils.summary import summarize

COLORS = {
    "critical": "#f87171",
    "high": "#fb923c",
    "medium": "#fbbf24",
    "low": "#60a5fa",
    "info": "#9ca3af",
}


def generate_html_report(findings: List[Finding], target: str, output_path: str | None = None, lang: str = "en") -> str:
    s = summarize(findings)
    rows = []
    for f in findings:
        color = COLORS.get(f.severity.value, "#fff")
        rec = f.recommendation or ""
        rows.append(
            f"<tr><td style='color:{color};font-weight:bold'>{f.severity.value}</td>"
            f"<td>{f.title}</td><td><code>{f.location}</code></td>"
            f"<td>{f.description}</td><td>{rec}</td></tr>"
        )
    title = "LocalVulnAI Report" if lang != "bn" else "LocalVulnAI রিপোর্ট"
    risk_l = "Risk" if lang != "bn" else "ঝুঁকি"
    html = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>{title}</title>
<style>
body{{font-family:system-ui;background:#0f1115;color:#e5e7eb;margin:2rem}}
table{{border-collapse:collapse;width:100%}}
td,th{{border:1px solid #333;padding:.5rem;text-align:left;vertical-align:top}}
code{{color:#93c5fd}}
.card{{background:#1a1d24;padding:1rem;border-radius:8px;margin-bottom:1rem}}
</style></head><body>
<h1>{title}</h1>
<div class="card">
<strong>Target:</strong> <code>{target}</code><br>
<strong>Date:</strong> {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}<br>
<strong>{risk_l}:</strong> {s['risk_score']} ({s['risk_level']}) — total {s['total']}
</div>
<table>
<tr><th>Severity</th><th>Title</th><th>Location</th><th>Description</th><th>Fix</th></tr>
{''.join(rows) if rows else '<tr><td colspan=5>No issues</td></tr>'}
</table>
</body></html>"""
    if output_path:
        Path(output_path).write_text(html, encoding="utf-8")
    return html
