from pathlib import Path
from typing import List
import re
from localvulnai.scanners.base import BaseScanner
from localvulnai.models.finding import Finding, Severity
from localvulnai.ai.ollama_client import OllamaClient


SUPPORTED_EXTENSIONS = {".py", ".js", ".ts", ".jsx", ".tsx", ".php", ".html", ".java", ".go"}

# Simple but useful pattern rules (fast, no AI needed)
PATTERN_RULES = [
    {
        "name": "Hard-coded secret / API key",
        "regex": re.compile(r"""(?i)(api[_-]?key|secret[_-]?key|access[_-]?token|aws_secret|password\s*=\s*['\"][^'\"]{4,})"""),
        "severity": Severity.HIGH,
        "description": "Possible hard-coded credential or secret found in source.",
        "recommendation": "Move secrets to environment variables or a secret manager. Never commit credentials.",
        "cwe": "CWE-798",
    },
    {
        "name": "Potential SQL injection (string formatting)",
        "regex": re.compile(r"""(?i)(execute|query|cursor\.execute)\s*\(.*(%s|%d|\.format\(|f['\"].*\{).*"""),
        "severity": Severity.HIGH,
        "description": "SQL query appears to be built with string formatting / interpolation.",
        "recommendation": "Use parameterized queries / prepared statements.",
        "cwe": "CWE-89",
    },
    {
        "name": "Potential command injection",
        "regex": re.compile(r"""(?i)(os\.system|subprocess\.(call|run|Popen)|exec\(|eval\()\s*\(.*(\+|format|f['\"])"""),
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
        # Limit for first versions to keep scans reasonable
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
        """Send code to local LLM and try to extract findings."""
        if not self.ai.is_available():
            return []

        # Limit size so we don't blow the context
        snippet = content[:6000]
        language = file_path.suffix.lstrip(".") or "unknown"

        try:
            raw = self.ai.analyze_code(snippet, language=language)
        except Exception:
            return []

        findings = []
        # Very lightweight parsing of AI response
        lower = raw.lower()
        if any(w in lower for w in ["vulnerability", "vulnerable", "injection", "xss", "secret", "insecure"]):
            # Create one summary finding from AI for now
            findings.append(
                Finding(
                    title="AI-detected potential security issue",
                    severity=Severity.MEDIUM,
                    description=raw[:800].strip(),
                    location=str(file_path),
                    recommendation="Review the AI analysis carefully and validate the issue manually.",
                    confidence=0.55,
                )
            )
        return findings

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

            # Fast pattern-based detection (always runs)
            findings.extend(self._pattern_scan(content, file_path))

            # Optional AI deep analysis (only if enabled and available)
            if self.use_ai:
                findings.extend(self._ai_scan(content, file_path))

        # Deduplicate by title + location
        seen = set()
        unique = []
        for f in findings:
            key = (f.title, f.location)
            if key not in seen:
                seen.add(key)
                unique.append(f)

        return unique
