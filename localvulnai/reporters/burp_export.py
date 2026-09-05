from typing import List
from pathlib import Path
import json
from localvulnai.models.finding import Finding


def generate_burp_friendly(findings: List[Finding], target: str, output_path: str | None = None) -> str:
    issues = []
    for f in findings:
        issues.append(
            {
                "name": f.title,
                "severity": f.severity.value,
                "host": target,
                "path": f.location,
                "description": f.description,
                "remediation": f.recommendation or "",
                "cwe": f.cwe or "",
                "evidence": f.evidence or "",
            }
        )
    data = {"target": target, "issue_count": len(issues), "issues": issues}
    content = json.dumps(data, indent=2, ensure_ascii=False)
    if output_path:
        Path(output_path).write_text(content, encoding="utf-8")
    return content
