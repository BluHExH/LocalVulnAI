from pathlib import Path
from typing import List
import re
from localvulnai.scanners.base import BaseScanner
from localvulnai.models.finding import Finding, Severity


class OpenAPIScanner(BaseScanner):
    def __init__(self, path: str):
        self.path = Path(path)

    def scan(self) -> List[Finding]:
        findings: List[Finding] = []
        root = self.path if self.path.is_dir() else self.path.parent
        files = list(root.rglob("openapi*.json")) + list(root.rglob("openapi*.y*ml"))
        files += list(root.rglob("swagger*.json")) + list(root.rglob("swagger*.y*ml"))
        for f in files[:10]:
            findings.extend(self._scan_file(f))
        return findings

    def _scan_file(self, path: Path) -> List[Finding]:
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return []
        findings = []
        if re.search(r"http://", text) and "localhost" not in text.lower():
            findings.append(
                Finding(
                    title="OpenAPI server uses HTTP",
                    severity=Severity.MEDIUM,
                    description="API spec references http:// servers — traffic may be plaintext.",
                    location=str(path),
                    recommendation="Use https:// in servers URL.",
                    confidence=0.6,
                )
            )
        if "security" not in text.lower():
            findings.append(
                Finding(
                    title="OpenAPI missing security schemes",
                    severity=Severity.LOW,
                    description="No security/securitySchemes section detected.",
                    location=str(path),
                    recommendation="Define auth requirements in the OpenAPI document.",
                    confidence=0.4,
                )
            )
        return findings
