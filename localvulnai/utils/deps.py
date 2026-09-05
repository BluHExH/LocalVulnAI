from pathlib import Path
from typing import List
from localvulnai.models.finding import Finding, Severity
import re


def scan_requirements(path: str) -> List[Finding]:
    p = Path(path)
    if p.is_dir():
        p = p / "requirements.txt"
    if not p.is_file():
        return []

    findings = []
    text = p.read_text(encoding="utf-8", errors="ignore")
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        if re.match(r"^[A-Za-z0-9_.-]+$", line):
            findings.append(
                Finding(
                    title=f"Unpinned dependency: {line}",
                    severity=Severity.LOW,
                    description="Package has no version pin; builds may pull vulnerable versions.",
                    location=str(p),
                    recommendation=f"Pin a version, e.g. {line}==x.y.z",
                    cwe="CWE-1104",
                    confidence=0.6,
                )
            )
    return findings
