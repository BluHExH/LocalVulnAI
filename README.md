# LocalVulnAI

**Local AI-powered vulnerability scanner** — patterns + optional Ollama, web checks, reports, CI, web UI.

> Authorized testing only.

## Highlights (v0.5)

- Code rules + known secret patterns (AWS/GitHub/Slack/Stripe…)
- Custom `rules.yml` patterns
- `--git-diff` (only changed files)
- Baseline ignore (`.localvulnai-ignore` + `baseline` command)
- Dependency heuristics (`requirements.txt`)
- Reports: md | json | sarif | burp | **html**
- Multi-target paths/URLs (comma-separated)
- `--webhook` Discord/Slack
- `--lang bn` for HTML report
- Pre-commit example, scheduled Actions, Docker, Codespaces, FastAPI UI

## Install

```bash
git clone https://github.com/BluHExH/LocalVulnAI.git && cd LocalVulnAI
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

## Usage

```bash
python -m localvulnai scan --path ./examples/sample_vulnerable_code --no-ai
python -m localvulnai scan --path ./a,./b --no-ai
python -m localvulnai scan --git-diff --no-ai
python -m localvulnai baseline --path .
python -m localvulnai scan --path . --no-ai --ignore .localvulnai-ignore
python -m localvulnai scan --path . --no-ai -o report.html -f html --lang bn
python -m localvulnai scan --url https://example.com --deep
python -m localvulnai scan --path . --no-ai --webhook https://hooks.slack.com/...

uvicorn localvulnai.web.app:app --port 8000
```

**Codespaces:** https://codespaces.new/BluHExH/LocalVulnAI

## License

MIT
