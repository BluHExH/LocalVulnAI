from pathlib import Path
from typing import List
from localvulnai.scanners.base import BaseScanner
from localvulnai.models.finding import Finding, Severity
from localvulnai.ai.ollama_client import OllamaClient


SUPPORTED_EXTENSIONS = {".py", ".js", ".ts", ".jsx", ".tsx", ".php", ".html", ".java", ".go"}


class CodeScanner(BaseScanner):
    def __init__(self, path: str, ai_client: OllamaClient | None = None):
        self.path = Path(path)
        self.ai = ai_client or OllamaClient()

    def _collect_files(self) -> List[Path]:
        if self.path.is_file():
            return [self.path] if self.path.suffix in SUPPORTED_EXTENSIONS else []

        files = []
        for ext in SUPPORTED_EXTENSIONS:
            files.extend(self.path.rglob(f"*{ext}"))
        return files[:50]  # safety limit for first version

    def scan(self) -> List[Finding]:
        findings: List[Finding] = []
        files = self._collect_files()

        if not files:
            return findings

        # Very basic pattern checks first (will improve later)
        for file_path in files:
            try:
                content = file_path.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue

            # Simple hardcoded secret heuristic
            if any(k in content.lower() for k in ["api_key", "secret_key", "password =", "aws_secret"]):
                findings.append(
                    Finding(
                        title="Possible hard-coded secret",
                        severity=Severity.HIGH,
                        description="Potential secret or credential found in source code.",
                        location=str(file_path),
                        recommendation="Move secrets to environment variables or a secret manager.",
                        confidence=0.6,
                    )
                )

        # TODO: In next iteration call self.ai.analyze_code() for deeper analysis
        return findings
