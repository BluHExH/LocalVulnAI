from pathlib import Path
from typing import List, Set
from localvulnai.models.finding import Finding
import hashlib


def _key(f: Finding) -> str:
    raw = f"{f.title}|{f.location}|{f.severity.value}"
    return hashlib.sha1(raw.encode()).hexdigest()[:16]


def load_ignore_keys(path: str | None = None) -> Set[str]:
    p = Path(path) if path else Path.cwd() / ".localvulnai-ignore"
    if not p.is_file():
        return set()
    keys = set()
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        keys.add(line.split()[0])
    return keys


def filter_ignored(findings: List[Finding], ignore_keys: Set[str]) -> List[Finding]:
    if not ignore_keys:
        return findings
    return [f for f in findings if _key(f) not in ignore_keys]


def write_baseline(findings: List[Finding], path: str = ".localvulnai-ignore") -> None:
    lines = ["# LocalVulnAI baseline — one fingerprint per line", "# title | location"]
    for f in findings:
        lines.append(f"{_key(f)}  # {f.title} @ {f.location}")
    Path(path).write_text("\n".join(lines) + "\n", encoding="utf-8")
