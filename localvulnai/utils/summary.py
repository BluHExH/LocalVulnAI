from typing import List, Dict
from localvulnai.models.finding import Finding, Severity

WEIGHTS = {
    Severity.CRITICAL: 10,
    Severity.HIGH: 5,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
    Severity.INFO: 0,
}


def summarize(findings: List[Finding]) -> Dict:
    counts = {s.value: 0 for s in Severity}
    for f in findings:
        counts[f.severity.value] += 1

    score = sum(WEIGHTS.get(f.severity, 0) for f in findings)
    risk = min(100, score)

    if risk >= 40:
        level = "critical"
    elif risk >= 20:
        level = "high"
    elif risk >= 8:
        level = "medium"
    elif risk >= 1:
        level = "low"
    else:
        level = "clean"

    return {
        "total": len(findings),
        "counts": counts,
        "risk_score": risk,
        "risk_level": level,
    }
