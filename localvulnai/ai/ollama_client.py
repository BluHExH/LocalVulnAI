from typing import Optional, List, Dict, Any
import re
import ollama
from localvulnai.config import settings
from localvulnai.models.finding import Finding, Severity


class OllamaClient:
    def __init__(self, model: Optional[str] = None, host: Optional[str] = None):
        self.model = model or settings.ollama_model
        self.host = host or settings.ollama_host
        self.client = ollama.Client(host=self.host)

    def is_available(self) -> bool:
        try:
            self.client.list()
            return True
        except Exception:
            return False

    def generate(self, prompt: str, system: Optional[str] = None) -> str:
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        response = self.client.chat(model=self.model, messages=messages)
        return response["message"]["content"]

    def analyze_code(self, code: str, language: str = "unknown") -> str:
        system = (
            "You are a senior application security engineer. "
            "Analyze the given code for REAL security vulnerabilities only. "
            "Ignore style issues. "
            "For each real issue reply in this exact format:\n"
            "TITLE: <short title>\n"
            "SEVERITY: <critical|high|medium|low>\n"
            "DESCRIPTION: <1-2 sentences>\n"
            "FIX: <short recommendation>\n"
            "---\n"
            "If no real issues found, reply exactly: NO_ISSUES"
        )
        prompt = f"Language: {language}\n\nCode:\n```\n{code}\n```"
        return self.generate(prompt, system=system)

    def parse_findings(self, raw: str, location: str) -> List[Finding]:
        """Parse structured AI response into Finding objects."""
        if not raw or "NO_ISSUES" in raw.upper():
            return []

        findings: List[Finding] = []
        blocks = re.split(r"\n---\n|\n\n(?=TITLE:)", raw)

        for block in blocks:
            block = block.strip()
            if not block or "TITLE:" not in block.upper():
                continue

            title_m = re.search(r"TITLE:\s*(.+)", block, re.I)
            sev_m = re.search(r"SEVERITY:\s*(critical|high|medium|low)", block, re.I)
            desc_m = re.search(r"DESCRIPTION:\s*(.+?)(?=\nFIX:|\nSEVERITY:|\nTITLE:|$)", block, re.I | re.S)
            fix_m = re.search(r"FIX:\s*(.+?)(?=\nTITLE:|\nSEVERITY:|\nDESCRIPTION:|$)", block, re.I | re.S)

            if not title_m:
                continue

            severity_str = (sev_m.group(1).lower() if sev_m else "medium")
            try:
                severity = Severity(severity_str)
            except ValueError:
                severity = Severity.MEDIUM

            findings.append(
                Finding(
                    title=title_m.group(1).strip()[:120],
                    severity=severity,
                    description=(desc_m.group(1).strip() if desc_m else "AI-detected issue").strip()[:600],
                    location=location,
                    recommendation=(fix_m.group(1).strip() if fix_m else None),
                    confidence=0.6,
                )
            )

        if not findings and any(w in raw.lower() for w in ["vulnerab", "injection", "xss", "secret", "insecure"]):
            findings.append(
                Finding(
                    title="AI-detected potential security issue",
                    severity=Severity.MEDIUM,
                    description=raw[:700].strip(),
                    location=location,
                    recommendation="Review the AI output carefully and validate manually.",
                    confidence=0.5,
                )
            )

        return findings
