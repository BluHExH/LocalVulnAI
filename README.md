# LocalVulnAI

**Local AI-powered vulnerability scanner**

Scan your code and websites offline using local LLMs (Ollama).  
Find common vulnerabilities, get clear explanations, and suggested fixes — all without sending any data to the cloud.

> ⚠️ **For authorized testing only.** Only scan systems and code you own or have explicit permission to test.

---

## Features

- **Local-first** — Runs completely on your machine with Ollama
- **Code scanning** — Analyze local source code (Python, JS, PHP, etc.)
- **Web scanning** — Basic live URL analysis
- **AI explanations** — Understand *why* something is vulnerable and how to fix it
- **Clean reports** — Markdown + JSON output
- **CLI focused** — Fast and scriptable

---

## Requirements

- Python 3.10+
- [Ollama](https://ollama.com) installed and running
- A local model pulled (recommended: `llama3.2`, `mistral`, or `qwen2.5`)

```bash
# Install Ollama (if not already installed)
# Then pull a model:
ollama pull llama3.2
```

---

## Installation

```bash
git clone https://github.com/BluHExH/LocalVulnAI.git
cd LocalVulnAI

python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate

pip install -r requirements.txt
```

---

## Usage

```bash
# Scan a local directory
python -m localvulnai scan --path ./your-project

# Scan a live URL (authorized targets only)
python -m localvulnai scan --url https://example.com

# Generate report
python -m localvulnai scan --path ./your-project --output report.md
```

---

## Project Status

**Phase 1 (Current)** — Core structure + basic CLI + Ollama integration skeleton

Coming next:
- Real code pattern detection + AI analysis
- Improved web scanning with Playwright
- Better reporting
- More language support

---

## Disclaimer

This tool is intended for **educational purposes** and **authorized security testing** only.  
The authors are not responsible for any misuse.

---

## License

MIT
