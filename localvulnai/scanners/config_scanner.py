from pathlib import Path
from typing import List
from localvulnai.scanners.base import BaseScanner
from localvulnai.models.finding import Finding, Severity
from localvulnai.utils.fix_snippets import snippet_for


class ConfigScanner(BaseScanner):
    """Scan Dockerfile and GitHub workflow YAML for common misconfigs."""

    def __init__(self, path: str):
        self.path = Path(path)

    def scan(self) -> List[Finding]:
        findings: List[Finding] = []
        root = self.path if self.path.is_dir() else self.path.parent
        for df in list(root.rglob("Dockerfile")) + list(root.rglob("Dockerfile.*")):
            findings.extend(self._scan_dockerfile(df))
        for wf in list(root.glob(".github/workflows/*.yml")) + list(root.glob(".github/workflows/*.yaml")):
            findings.extend(self._scan_workflow(wf))
        return findings[:30]

    def _scan_dockerfile(self, path: Path) -> List[Finding]:
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return []
        findings = []
        lower = text.lower()
        if "\nuser " not in lower and not lower.strip().startswith("user "):
            findings.append(
                Finding(
                    title="Dockerfile may run as root",
                    severity=Severity.MEDIUM,
                    description="No USER directive found — container may run as root.",
                    location=str(path),
                    recommendation="Add a non-root USER instruction.",
                    fix_snippet=snippet_for("dockerfile"),
                    cwe="CWE-250",
                    confidence=0.5,
                )
            )
        if "--privileged" in lower or "privileged: true" in lower:
            findings.append(
                Finding(
                    title="Privileged container flag",
                    severity=Severity.HIGH,
                    description="Privileged mode greatly increases breakout risk.",
                    location=str(path),
                    recommendation="Avoid privileged containers.",
                    cwe="CWE-250",
                    confidence=0.8,
                )
            )
        if "add http://" in lower:
            findings.append(
                Finding(
                    title="Dockerfile ADD over HTTP",
                    severity=Severity.MEDIUM,
                    description="Fetching build context over plain HTTP is insecure.",
                    location=str(path),
                    recommendation="Use HTTPS and verify checksums.",
                    confidence=0.7,
                )
            )
        return findings

    def _scan_workflow(self, path: Path) -> List[Finding]:
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return []
        findings = []
        if "pull_request_target" in text and "checkout" in text.lower():
            findings.append(
                Finding(
                    title="pull_request_target with checkout",
                    severity=Severity.HIGH,
                    description="pull_request_target + checkout of PR code can lead to secret theft.",
                    location=str(path),
                    recommendation="Prefer pull_request; never expose secrets to untrusted code.",
                    cwe="CWE-1385",
                    confidence=0.6,
                )
            )
        if "curl " in text.lower() and "| bash" in text.lower():
            findings.append(
                Finding(
                    title="curl | bash in workflow",
                    severity=Severity.MEDIUM,
                    description="Piping remote scripts to bash is risky in CI.",
                    location=str(path),
                    recommendation="Pin versions and verify integrity.",
                    confidence=0.65,
                )
            )
        return findings
