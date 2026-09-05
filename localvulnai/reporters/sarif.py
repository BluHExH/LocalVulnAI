from typing import List
from pathlib import Path
import json
from localvulnai.models.finding import Finding

LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}


def generate_sarif_report(findings: List[Finding], target: str, output_path: str | None = None) -> str:
    results = []
    for i, f in enumerate(findings):
        results.append(
            {
                "ruleId": f.cwe or f"localvulnai/{i}",
                "level": LEVEL.get(f.severity.value, "warning"),
                "message": {"text": f"{f.title}: {f.description}"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": f.location},
                        }
                    }
                ],
                "properties": {
                    "severity": f.severity.value,
                    "recommendation": f.recommendation,
                    "confidence": f.confidence,
                },
            }
        )

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "LocalVulnAI",
                        "version": "0.4.0",
                        "informationUri": "https://github.com/BluHExH/LocalVulnAI",
                    }
                },
                "results": results,
                "properties": {"target": target},
            }
        ],
    }
    content = json.dumps(sarif, indent=2)
    if output_path:
        Path(output_path).write_text(content, encoding="utf-8")
    return content
