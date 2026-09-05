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
- **Deep web mode** — Playwright checks (forms, mixed content, password over HTTP)
- **Reports** — Markdown + JSON
- **CLI focused** — Fast and scriptable

### Code detection
- Hard-coded secrets / API keys
- SQL injection (string formatting)
- Command injection
- Dangerous `eval` / `exec`
- Potential XSS patterns
- Insecure deserialization
- AI-assisted findings (structured parsing)

### Web detection
- Missing CSP, HSTS, X-Frame-Options, X-Content-Type-Options
- Referrer-Policy, Permissions-Policy
- Server / X-Powered-By disclosure
- Cookies missing Secure / HttpOnly
- `--deep`: password over HTTP, CSRF heuristic, mixed content

---

## Requirements

- Python 3.10+
- [Ollama](https://ollama.com) (optional but recommended)
- For deep web scans: Playwright browsers

```bash
ollama pull llama3.2
playwright install chromium   # only if you use --deep
```

---

## Installation

```bash
git clone https://github.com/BluHExH/LocalVulnAI.git
cd LocalVulnAI

python -m venv .venv
source .venv/bin/activate

pip install -r requirements.txt
```

---

## Usage

```bash
python -m localvulnai check

# Code scan
python -m localvulnai scan --path ./your-project
python -m localvulnai scan --path ./your-project --no-ai

# Web scan
python -m localvulnai scan --url https://example.com
python -m localvulnai scan --url https://example.com --deep

# Reports
python -m localvulnai scan --path ./examples/sample_vulnerable_code -o report.md
python -m localvulnai scan --path ./examples/sample_vulnerable_code -o report.json --format json
```

---

## Project Status

**v0.3.0**
- Pattern + AI code scanner
- Web header/cookie scanner
- Playwright deep mode
- Markdown + JSON reports

---

## Disclaimer

Educational and **authorized** security testing only.

## License

MIT
