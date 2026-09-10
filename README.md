# LocalVulnAI

<p align="center">
  <strong>Local AI-powered vulnerability scanner</strong><br/>
  Patterns + optional Ollama · Beautiful CLI · CI-ready
</p>

<p align="center">
  <a href="https://github.com/BluHExH/LocalVulnAI"><img src="https://img.shields.io/github/stars/BluHExH/LocalVulnAI?style=for-the-badge&logo=github" alt="Stars"/></a>
  <img src="https://img.shields.io/badge/version-0.6.0-blue?style=for-the-badge" alt="Version"/>
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="MIT"/>
  <img src="https://img.shields.io/badge/Python-3.10%2B-blue?style=for-the-badge&logo=python&logoColor=white" alt="Python"/>
</p>

> Authorized testing only.

## Preview

<p align="center">
  <img src="docs/screenshots/scan-summary.svg" alt="CLI preview" width="720"/>
</p>

## v0.6 highlights

- `--fail-on high` — CI exit code when severity threshold hit
- `init` — create config / ignore / rules files
- HTML report — dark UI, severity filters, Print/PDF
- Fix code snippets on findings
- Authenticated web scan — `-H` / `--cookie`
- Dockerfile + GitHub Actions misconfig checks
- OpenAPI/Swagger heuristics
- Rich Slack/Discord webhooks

## Quick start

```bash
git clone https://github.com/BluHExH/LocalVulnAI.git
cd LocalVulnAI
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

python -m localvulnai init
python -m localvulnai scan --path ./examples/sample_vulnerable_code --no-ai --fail-on high
python -m localvulnai scan --path . --no-ai -o report.html -f html
```

**Codespaces:** https://codespaces.new/BluHExH/LocalVulnAI

## Commands

```bash
python -m localvulnai init
python -m localvulnai scan --path ./src --no-ai --fail-on high
python -m localvulnai scan --url https://example.com -H "Authorization: Bearer TOKEN" --cookie "session=abc"
python -m localvulnai scan --git-diff --no-ai
python -m localvulnai baseline --path .
python -m localvulnai scan --path . --no-ai -o out.sarif -f sarif
```

## License

MIT
