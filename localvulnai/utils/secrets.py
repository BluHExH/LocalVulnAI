import re
from typing import List, Tuple

SECRET_PATTERNS: List[Tuple[str, re.Pattern, str]] = [
    ("AWS Access Key", re.compile(r"AKIA[0-9A-Z]{16}"), "high"),
    ("GitHub token", re.compile(r"ghp_[A-Za-z0-9]{36}"), "critical"),
    ("GitHub fine-grained", re.compile(r"github_pat_[A-Za-z0-9_]{20,}"), "critical"),
    ("Slack token", re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"), "high"),
    ("Stripe secret", re.compile(r"sk_live_[A-Za-z0-9]{20,}"), "critical"),
    ("Google API key", re.compile(r"AIza[0-9A-Za-z\-_]{35}"), "high"),
    ("Private key block", re.compile(r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----"), "critical"),
    ("JWT-like secret", re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"), "medium"),
]


def find_secrets(content: str) -> List[Tuple[str, str]]:
    hits = []
    for name, rx, _sev in SECRET_PATTERNS:
        m = rx.search(content)
        if m:
            hits.append((name, m.group(0)[:20] + "..."))
    return hits
