import subprocess
from pathlib import Path
from typing import List


def changed_files(repo: str = ".", base: str = "HEAD~1") -> List[Path]:
    try:
        out = subprocess.check_output(
            ["git", "-C", repo, "diff", "--name-only", "--diff-filter=ACMR", base],
            text=True,
            stderr=subprocess.DEVNULL,
        )
    except Exception:
        return []
    root = Path(repo).resolve()
    files = []
    for line in out.splitlines():
        p = root / line.strip()
        if p.is_file():
            files.append(p)
    return files
