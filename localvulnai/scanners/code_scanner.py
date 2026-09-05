from pathlib import Path
from typing import List
import re
from localvulnai.scanners.base import BaseScanner
from localvulnai.models.finding import Finding, Severity
from localvulnai.ai.ollama_client import OllamaClient


SUPPORTED_EXTENSIONS = {".py", ".js", ".ts", ".jsx", ".tsx", ".php", ".html", ".java", ".go", ".rb", ".cs"}

PATTERN_RULES = [
    {
        "name": "Hard-coded secret / API key",
        "regex": re.compile(
            r"""(?i)(api[_-]?key|secret[_-]?key|access[_-]?token|aws_secret|password\s*=\s*['\"][^'\"]{4,}|sk-[a-zA-Z0-9]{20,})"""
        ),
        "severity": Severity.HIGH,
        "description": "Possible hard-coded credential or secret found in source.",
        "recommendation": "Move secrets to environment variables or a secret manager. Never commit credentials.",
        "cwe": "CWE-798",
    },
    {
        "name": "Potential SQL injection (string formatting)",
        "regex": re.compile(
            r"""(?i)(execute|query|cursor\.execute|raw\()\s*\(.*(%s|%d|\.format\(|f['\"].*\{|'\s*\+)"""
        ),
        "severity": Severity.HIGH,
        "description": "SQL query appears to be built with string formatting / interpolation.",
        "recommendation": "Use parameterized queries / prepared statements.",
        "cwe": "CWE-89",
    },
    {
        "name": "Potential command injection",
        "regex": re.compile(
            r"""(?i)(os\.system|subprocess\.(call|run|Popen)|exec\(|popen\()\s*\(.*(\+|format|f['\"])"""
        ),
        "severity": Severity.CRITICAL,
        "description": "Possible command injection via dynamic command construction.",
        "recommendation": "Avoid shell=True. Use argument lists and never pass unsanitized user input.",
        "cwe": "CWE-78",
    },
    {
        "name": "Dangerous eval / exec",
        "regex": re.compile(r"""(?i)\b(eval|exec)\s*\("""),
        "severity": Severity.HIGH,
        "description": "Use of eval() or exec() can lead to code injection.",
        "recommendation": "Avoid eval/exec. Use safer alternatives (ast.literal_eval, json, etc.).",
        "cwe": "CWE-95",
    },
    {
        "name": "Potential XSS (unsanitized output)",
        "regex": re.compile(
            r"""(?i)(innerHTML\s*=|document\.write\s*\(|dangerouslySetInnerHTML|\.html\(\s*[^=])"""
        ),
        "severity": Severity.MEDIUM,
        "description": "Possible cross-site scripting via unsafe DOM / HTML rendering.",
        "recommendation": "Sanitize user input and prefer textContent or safe templating.",
        "cwe": "CWE-79",
    },
    {
        "name": "Insecure deserialization",
        "regex": re.compile(r"""(?i)(pickle\.loads|yaml\.load\s*\(|marshal\.loads|unserialize\s*\()"""),
        "severity": Severity.HIGH,
        "description": "Insecure deserialization can lead to remote code execution.",
        "recommendation": "Avoid deserializing untrusted data. Use safe formats (JSON) with validation.",
        "cwe": "CWE-502",
    },
]


class CodeScanner(BaseScanner):
    def __init__(self, path: str, ai_client: OllamaClient | None = None, use_ai: bool = True):
        self.path = Path(path)
        self.ai = ai_client or OllamaClient()
        self.use_ai = use_ai

    def _collect_files(self) -> List[Path]:
        if self.path.is_file():
            return [self.path] if self.path.suffix in SUPPORTED_EXTENSIONS else []

        files = []
        for ext in SUPPORTED_EXTENSIONS:
            files.extend(self.path.rglob(f"*{ext}"))
        return files[:40]

    def _pattern_scan(self, content: str, file_path: Path) -> List[Finding]:
        findings = []
        for rule in PATTERN_RULES:
            if rule["regex"].search(content):
                findings.append(
                    Finding(
                        title=rule["name"],
                        severity=rule["severity"],
                        description=rule["description"],
                        location=str(file_path),
                        recommendation=rule["recommendation"],
                        cwe=rule.get("cwe"),
                        confidence=0.75,
                    )
                )
        return findings

    def _ai_scan(self, content: str, file_path: Path) -> List[Finding]:
        if not self.ai.is_available():
            return []

        snippet = content[:6000]
        language = file_path.suffix.lstrip(".") or "unknown"

        try:
            raw = self.ai.analyze_code(snippet, language=language)
            return self.ai.parse_findings(raw, str(file_path))
        except Exception:
            return []

    def scan(self) -> List[Finding]:
        findings: List[Finding] = []
        files = self._collect_files()

        if not files:
            return findings

        for file_path in files:
            try:
                content = file_path.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue

            if not content.strip():
                continue

            findings.extend(self._pattern_scan(content, file_path))

            if self.use_ai:
                findings.extend(self._ai_scan(content, file_path))

        seen = set()
        unique = []
        for f in findings:
            key = (f.title.lower(), f.location)
            if key not in seen:
                seen.add(key)
                unique.append(f)

        return unique
