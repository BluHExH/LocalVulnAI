"""Simple web UI for LocalVulnAI - FastAPI."""
from fastapi import FastAPI, Form
from fastapi.responses import HTMLResponse
from localvulnai.scanners.code_scanner import CodeScanner
from localvulnai.scanners.web_scanner import WebScanner
from localvulnai.utils.summary import summarize

app = FastAPI(title="LocalVulnAI", version="0.4.0")

PAGE = """
<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>LocalVulnAI</title>
<style>
body{font-family:system-ui;max-width:900px;margin:2rem auto;padding:0 1rem;background:#0f1115;color:#e6e6e6}
input,button{padding:.6rem;margin:.3rem 0;border-radius:6px;border:1px solid #333;background:#1a1d24;color:#fff}
button{background:#3b82f6;cursor:pointer;border:none}
table{width:100%;border-collapse:collapse;margin-top:1rem}
td,th{border:1px solid #333;padding:.5rem;text-align:left}
.crit{color:#f87171}.high{color:#fb923c}.med{color:#fbbf24}
</style></head><body>
<h1>LocalVulnAI</h1>
<p>Authorized testing only.</p>
<form method="post">
  <div><label>Path (local code)</label><br><input name="path" size="60" placeholder="./project"></div>
  <div><label>URL (web)</label><br><input name="url" size="60" placeholder="https://example.com"></div>
  <label><input type="checkbox" name="no_ai" value="1"> Pattern only (no AI)</label>
  <label><input type="checkbox" name="deep" value="1"> Deep web (Playwright)</label><br>
  <button type="submit">Scan</button>
</form>
{result}
</body></html>
"""


@app.get("/", response_class=HTMLResponse)
def home():
    return PAGE.format(result="")


@app.post("/", response_class=HTMLResponse)
def run_scan(
    path: str = Form(""),
    url: str = Form(""),
    no_ai: str = Form(""),
    deep: str = Form(""),
):
    findings = []
    target = path or url
    err = ""
    if path and url:
        err = "Use either path or URL"
    elif not path and not url:
        err = "Provide path or URL"
    elif path:
        findings = CodeScanner(path, use_ai=not bool(no_ai)).scan()
    else:
        findings = WebScanner(url, deep=bool(deep)).scan()

    if err:
        result = f"<p style='color:#f87171'>{err}</p>"
    else:
        s = summarize(findings)
        rows = "".join(
            f"<tr><td class='{f.severity.value[:4]}'>{f.severity.value}</td>"
            f"<td>{f.title}</td><td><code>{f.location}</code></td></tr>"
            for f in findings
        )
        result = (
            f"<h2>Results for <code>{target}</code></h2>"
            f"<p>Total: {s['total']} | Risk: {s['risk_score']} ({s['risk_level']})</p>"
            f"<table><tr><th>Severity</th><th>Title</th><th>Location</th></tr>{rows or '<tr><td colspan=3>No issues</td></tr>'}</table>"
        )
    return PAGE.format(result=result)


def main():
    import uvicorn
    uvicorn.run("localvulnai.web.app:app", host="127.0.0.1", port=8000, reload=False)


if __name__ == "__main__":
    main()
