# LocalVulnAI

**Local AI-powered vulnerability scanner**

Scan code and websites offline with pattern rules + optional local LLM (Ollama).  
Markdown / JSON / SARIF / Burp-friendly reports. Small web UI included.

> ⚠️ **Authorized testing only.**

## Features

- Code patterns: secrets, SQLi, command injection, eval, XSS, deserialization, weak hash, debug mode, path traversal, open redirect, SSRF hints
- Optional AI analysis (Ollama) with structured findings
- Web: security headers, cookies, optional Playwright `--deep`
- Reports: `md` | `json` | `sarif` | `burp`
- Risk summary score
- Config file `.localvulnai.yml`
- GitHub Actions + SARIF upload example
- FastAPI web UI
- Docker + GitHub Codespaces

## Install

```bash
git clone https://github.com/BluHExH/LocalVulnAI.git
cd LocalVulnAI
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
# optional:
ollama pull llama3.2
playwright install chromium
```

## CLI

```bash
python -m localvulnai check
python -m localvulnai scan --path ./examples/sample_vulnerable_code --no-ai
python -m localvulnai scan --path ./src -o report.sarif -f sarif
python -m localvulnai scan --path ./src -o burp.json -f burp
python -m localvulnai scan --url https://example.com --deep
python -m localvulnai scan --path ./src -c .localvulnai.yml
```

## Web UI

```bash
pip install -r requirements.txt
uvicorn localvulnai.web.app:app --host 127.0.0.1 --port 8000
# open http://127.0.0.1:8000
```

## Cloud shell

**Codespaces:** https://codespaces.new/BluHExH/LocalVulnAI

## Docker

```bash
docker build -t localvulnai .
docker run --rm localvulnai scan --path /app/examples/sample_vulnerable_code --no-ai
```

## Config (`.localvulnai.yml`)

```yaml
extensions: [.py, .js, .ts]
max_files: 40
disabled_rules: []   # e.g. [weak-hash, debug-true]
```

## License

MIT
