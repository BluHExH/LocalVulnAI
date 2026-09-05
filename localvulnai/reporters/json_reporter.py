from typing import List
from pathlib import Path
import json
from datetime import datetime, timezone
from localvulnai.models.finding import Finding
from localvulnai.utils.summary import summarize


def generate_json_report(findings: List[Finding], target: str, output_path: str | None = None) -> str:
    summary = summarize(findings)
    data = {
        "tool": "LocalVulnAI",
        "version": "0.4.0",
        "target": target,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "summary": summary,
        "findings_count": len(findings),
        "findings": [
            {
                "title": f.title,
                "severity": f.severity.value,
                "description": f.description,
                "location": f.location,
                "recommendation": f.recommendation,
                "cwe": f.cwe,
                "confidence": f.confidence,
                "evidence": f.evidence,
            }
            for f in findings
        ],
    }
    content = json.dumps(data, indent=2, ensure_ascii=False)
    if output_path:
        Path(output_path).write_text(content, encoding="utf-8")
    return content
