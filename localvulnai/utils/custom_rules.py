from pathlib import Path
from typing import List, Dict, Any
import re
import yaml
from localvulnai.models.finding import Finding, Severity


def load_custom_rules(path: str | None = None) -> List[Dict[str, Any]]:
    p = Path(path) if path else Path.cwd() / "rules.yml"
    if not p.is_file():
        return []
    data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    return data.get("rules", [])


def apply_custom_rules(content: str, location: str, rules: List[Dict[str, Any]]) -> List[Finding]:
    findings = []
    for rule in rules:
        pattern = rule.get("pattern")
        if not pattern:
            continue
        try:
            rx = re.compile(pattern, re.I | re.M)
        except re.error:
            continue
        if rx.search(content):
            sev = rule.get("severity", "medium").lower()
            try:
                severity = Severity(sev)
            except ValueError:
                severity = Severity.MEDIUM
            findings.append(
                Finding(
                    title=rule.get("id") or rule.get("name") or "Custom rule match",
                    severity=severity,
                    description=rule.get("description") or "Matched custom rule.",
                    location=location,
                    recommendation=rule.get("recommendation"),
                    cwe=rule.get("cwe"),
                    confidence=0.7,
                )
            )
    return findings
