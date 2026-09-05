from typing import List
from pathlib import Path
from localvulnai.models.finding import Finding
from datetime import datetime


def generate_markdown_report(findings: List[Finding], target: str, output_path: str | None = None) -> str:
    lines = [
        f"# LocalVulnAI Scan Report",
        "",
        f"**Target:** `{target}`",
        f"**Date:** {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}",
        f"**Findings:** {len(findings)}",
        "",
        "---",
        "",
    ]

    if not findings:
        lines.append("No issues found.")
    else:
        # Sort by severity
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        sorted_findings = sorted(findings, key=lambda f: order.get(f.severity.value, 5))

        for finding in sorted_findings:
            lines.append(finding.to_markdown())
            lines.append("\n---\n")

    content = "\n".join(lines)

    if output_path:
        Path(output_path).write_text(content, encoding="utf-8")

    return content
