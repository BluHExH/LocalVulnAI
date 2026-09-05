# LocalVulnAI

**Local AI-powered vulnerability scanner**

Scan your code and websites offline using local LLMs (Ollama).  
Find common vulnerabilities, get clear explanations, and suggested fixes — all without sending any data to the cloud.

> ⚠️ **For authorized testing only.** Only scan systems and code you own or have explicit permission to test.

---

## Features

- **Local-first** — Runs completely on your machine with Ollama
- **Code scanning** — Strong pattern rules + optional AI deep analysis
- **Web scanning** — Security headers, cookies, info disclosure
- **Reports** — Markdown + JSON
- **CLI focused** — Fast and scriptable
- **No cloud** — Your code never leaves your machine

### Code detection
- Hard-coded secrets / API keys
- SQL injection (string formatting)
- Command injection
- Dangerous `eval` / `exec`
- Potential XSS patterns
- Insecure deserialization
- AI-assisted findings (structured parsing)

### Web detection
- Missing CSP, HSTS, X-Frame-Options
- Missing X-Content-Type-Options, Referrer-Policy, Permissions-Policy
- Server / X-Powered-By disclosure
- Cookies missing Secure / HttpOnly flags

---

## Requirements

- Python 3.10+
- [Ollama](https://ollama.com) (optional but recommended)
- Recommended models: `llama3.2`, `mistral`, `qwen2.5`

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
# Check Ollama
python -m localvulnai check

# Scan local code (pattern + AI)
python -m localvulnai scan --path ./your-project

# Fast pattern-only scan
python -m localvulnai scan --path ./your-project --no-ai

# Scan authorized URL
python -m localvulnai scan --url https://example.com

# Save Markdown report
python -m localvulnai scan --path ./examples/sample_vulnerable_code -o report.md

# Save JSON report
python -m localvulnai scan --path ./examples/sample_vulnerable_code -o report.json --format json
```

---

## Project Status

**v0.2.0**
- Working CLI
- Pattern-based code scanner (multiple rules)
- Structured AI analysis via Ollama
- Improved web header + cookie checks
- Markdown + JSON reports

**Later ideas**
- Playwright deeper web checks
- Burp-friendly export
- More language-specific rules

---

## Disclaimer

This tool is for **educational purposes** and **authorized security testing** only.  
The authors are not responsible for any misuse.

---

## License

MIT
