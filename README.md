# LocalVulnAI

**Local AI-powered vulnerability scanner**

Scan your code and websites offline using local LLMs (Ollama).  
Find common vulnerabilities, get clear explanations, and suggested fixes — all without sending any data to the cloud.

> ⚠️ **For authorized testing only.** Only scan systems and code you own or have explicit permission to test.

---

## Features

- **Local-first** — Runs completely on your machine with Ollama
- **Code scanning** — Pattern rules + optional AI deep analysis
- **Web scanning** — Basic live URL security header checks
- **Clean reports** — Markdown output
- **CLI focused** — Fast and scriptable
- **No cloud** — Your code never leaves your machine

### Currently detects (Code)
- Hard-coded secrets / API keys
- Potential SQL injection (string formatting)
- Command injection patterns
- Dangerous `eval` / `exec`
- AI-assisted findings (when Ollama is available)

### Currently detects (Web)
- Missing Content-Security-Policy
- Missing X-Frame-Options / clickjacking protection
- Missing HSTS
- Server header information disclosure

---

## Requirements

- Python 3.10+
- [Ollama](https://ollama.com) (optional but recommended)
- A local model (recommended: `llama3.2`, `mistral`, or `qwen2.5`)

```bash
ollama pull llama3.2
```

---

## Installation

```bash
git clone https://github.com/BluHExH/LocalVulnAI.git
cd LocalVulnAI

python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate

pip install -r requirements.txt
```

---

## Usage

```bash
# Check if Ollama is ready
python -m localvulnai check

# Scan a local directory (pattern + AI)
python -m localvulnai scan --path ./your-project

# Faster pattern-only scan (no AI)
python -m localvulnai scan --path ./your-project --no-ai

# Scan a live URL (authorized targets only)
python -m localvulnai scan --url https://example.com

# Save full report
python -m localvulnai scan --path ./examples/sample_vulnerable_code --output report.md
```

---

## Project Status

**v0.1.0** — Working core:
- CLI
- Pattern-based code scanner
- Optional AI analysis via Ollama
- Basic web header scanner
- Markdown reports

**Next planned:**
- Better AI response parsing into structured findings
- More language-specific rules
- Playwright-based deeper web checks
- JSON report format
- Burp-friendly export (later)

---

## Disclaimer

This tool is intended for **educational purposes** and **authorized security testing** only.  
The authors are not responsible for any misuse.

---

## License

MIT
