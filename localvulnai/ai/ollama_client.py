from typing import Optional
import ollama
from localvulnai.config import settings


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
            "Analyze the given code for security vulnerabilities. "
            "Be precise. Only report real issues. "
            "For each issue give: title, severity (critical/high/medium/low), "
            "short description, and a fix recommendation."
        )
        prompt = f"Language: {language}\n\nCode:\n```\n{code}\n```\n\nFind security issues:"
        return self.generate(prompt, system=system)
