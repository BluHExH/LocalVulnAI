from typing import List, Optional
import httpx
from localvulnai.models.finding import Finding
from localvulnai.utils.summary import summarize


def notify_webhook(url: Optional[str], findings: List[Finding], target: str) -> bool:
    if not url:
        return False
    s = summarize(findings)
    text = (
        f"LocalVulnAI scan: `{target}`\n"
        f"Findings: {s['total']} | Risk: {s['risk_score']} ({s['risk_level']})\n"
        f"crit={s['counts']['critical']} high={s['counts']['high']} med={s['counts']['medium']}"
    )
    payload = {"text": text, "content": text}
    try:
        r = httpx.post(url, json=payload, timeout=10.0)
        return r.status_code < 400
    except Exception:
        return False
