from typing import List
from localvulnai.models.finding import Finding, severity_at_least


def should_fail(findings: List[Finding], fail_on: str | None) -> bool:
    if not fail_on or fail_on.lower() in ("none", "off", ""):
        return False
    return any(severity_at_least(f.severity, fail_on) for f in findings)
