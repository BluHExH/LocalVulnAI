from pathlib import Path
from typing import List, Optional
import re
from localvulnai.scanners.base import BaseScanner
from localvulnai.models.finding import Finding, Severity
from localvulnai.ai.ollama_client import OllamaClient
from localvulnai.config import ScanConfig, load_scan_config


PATTERN_RULES = [
    {
        "id": "hardcoded-secret",
        "name": "Hard-coded secret / API key",
        "regex": re.compile(
            r"""(?i)(api[_-]?key|secret[_-]?key|access[_-]?token|aws_secret|password\s*=\s*['\"][^'\"]{4,}|sk-[a-zA-Z0-9]{20,})"""
        ),
        "severity": Severity.HIGH,
        "description": "Possible hard-coded credential or secret found in source.",
        "recommendation": "Move secrets to environment variables or a secret manager.",
        "cwe": "CWE-798",
    },
    {
        "id": "sqli-format",
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
        "id": "cmd-injection",
        "name": "Potential command injection",
        "regex": re.compile(
            r"""(?i)(os\.system|subprocess\.(call|run|Popen)|exec\(|popen\()\s*\(.*(\+|format|f['\"])"""
        ),
        "severity": Severity.CRITICAL,
        "description": "Possible command injection via dynamic command construction.",
        "recommendation": "Avoid shell=True. Use argument lists; never pass unsanitized input.",
        "cwe": "CWE-78",
    },
    {
        "id": "dangerous-eval",
        "name": "Dangerous eval / exec",
        "regex": re.compile(r"""(?i)\b(eval|exec)\s*\("""),
        "severity": Severity.HIGH,
        "description": "Use of eval() or exec() can lead to code injection.",
        "recommendation": "Avoid eval/exec. Use safer alternatives (ast.literal_eval, json).",
        "cwe": "CWE-95",
    },
    {
        "id": "xss-dom",
        "name": "Potential XSS (unsanitized output)",
        "regex": re.compile(
            r"""(?i)(innerHTML\s*=|document\.write\s*\(|dangerouslySetInnerHTML|\.html\(\s*[^=])"""
        ),
        "severity": Severity.MEDIUM,
        "description": "Possible cross-site scripting via unsafe DOM / HTML rendering.",
        "recommendation": "Sanitize user input; prefer textContent or safe templating.",
        "cwe": "CWE-79",
    },
    {
        "id": "insecure-deser",
        "name": "Insecure deserialization",
        "regex": re.compile(r"""(?i)(pickle\.loads|yaml\.load\s*\(|marshal\.loads|unserialize\s*\()"""),
        "severity": Severity.HIGH,
        "description": "Insecure deserialization can lead to remote code execution.",
        "recommendation": "Avoid deserializing untrusted data. Prefer JSON with validation.",
        "cwe": "CWE-502",
    },
    {
        "id": "weak-hash",
        "name": "Weak cryptographic hash",
        "regex": re.compile(r"""(?i)(hashlib\.(md5|sha1)\(|MD5\(|SHA1\()"""),
        "severity": Severity.MEDIUM,
        "description": "MD5/SHA1 are weak for password hashing or integrity of security data.",
        "recommendation": "Use SHA-256+ for integrity; use bcrypt/argon2/scrypt for passwords.",
        "cwe": "CWE-328",
    },
    {
        "id": "debug-true",
        "name": "Debug mode enabled",
        "regex": re.compile(r"""(?i)(DEBUG\s*=\s*True|app\.run\s*\(.*debug\s*=\s*True)"""),
        "severity": Severity.MEDIUM,
        "description": "Debug mode appears enabled, which can leak sensitive information.",
        "recommendation": "Disable debug in production environments.",
        "cwe": "CWE-489",
    },
    {
        "id": "path-traversal",
        "name": "Potential path traversal",
        "regex": re.compile(
            r"""(?i)(open\s*\(.*(\+|format|f['\"]).*(request|input|param|user)|send_file\s*\(.*\+)"""
        ),
        "severity": Severity.HIGH,
        "description": "File path may be influenced by user input without sanitization.",
        "recommendation": "Validate and canonicalize paths; reject '..' segments.",
        "cwe": "CWE-22",
    },
    {
        "id": "open-redirect",
        "name": "Potential open redirect",
        "regex": re.compile(
            r"""(?i)(redirect\s*\(.*request\.|RedirectResponse\s*\(.*\+|header\s*\(\s*['\"]location['\"]\s*,\s*.*\+)"""
        ),
        "severity": Severity.MEDIUM,
        "description": "Redirect target may be controlled by user input.",
        "recommendation": "Allowlist redirect destinations; never redirect to raw user URLs.",
        "cwe": "CWE-601",
    },
    {
        "id": "ssrf-hint",
        "name": "Potential SSRF (URL from input)",
        "regex": re.compile(
            r"""(?i)(requests\.(get|post|put|delete)\s*\(.*(\+|format|f['\"])|urlopen\s*\(.*(\+|format))"""
        ),
        "severity": Severity.MEDIUM,
        "description": "HTTP request URL may be built from dynamic/user-controlled data.",
        "recommendation": "Allowlist hosts; block private IP ranges for server-side fetches.",
        "cwe": "CWE-918",
    },
]


class CodeScanner(BaseScanner):
    def __init__(
        self,
        path: str,
        ai_client: OllamaClient | None = None,
        use_ai: bool = True,
        config: Optional[ScanConfig] = None,
    ):
        self.path = Path(path)
        self.ai = ai_client or OllamaClient()
        self.use_ai = use_ai
        self.config = config or load_scan_config()

    def _collect_files(self) -> List[Path]:
        exts = set(self.config.extensions)
        if self.path.is_file():
            return [self.path] if self.path.suffix in exts else []

        files = []
        for ext in exts:
            files.extend(self.path.rglob(f"*{ext}"))
        return files[: self.config.max_files]

    def _pattern_scan(self, content: str, file_path: Path) -> List[Finding]:
        findings = []
        disabled = set(self.config.disabled_rules)
        for rule in PATTERN_RULES:
            if rule["id"] in disabled:
                continue
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
