from pathlib import Path

YML = """# LocalVulnAI configuration
extensions:
  - .py
  - .js
  - .ts
  - .jsx
  - .tsx
  - .php
  - .html
  - .java
  - .go
  - .rb
  - .cs
max_files: 80
disabled_rules: []
# ollama_model: llama3.2
"""

IGNORE = """# LocalVulnAI baseline ignore file
# Run: python -m localvulnai baseline --path .
# Each line: fingerprint  # comment
"""

RULES = """rules:
  - id: no-verify-false
    pattern: "verify\\\\s*=\\\\s*False"
    severity: high
    description: TLS verification disabled
    recommendation: Never disable certificate verification in production
    cwe: CWE-295
"""


def init_files(root: str = ".") -> list[str]:
    base = Path(root)
    created = []
    mapping = {
        ".localvulnai.yml": YML,
        ".localvulnai-ignore": IGNORE,
        "rules.yml": RULES,
    }
    for name, content in mapping.items():
        path = base / name
        if not path.exists():
            path.write_text(content, encoding="utf-8")
            created.append(str(path))
    return created
