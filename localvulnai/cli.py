from typing import Optional, List
import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn

from localvulnai import __version__
from localvulnai.ai.ollama_client import OllamaClient
from localvulnai.scanners.code_scanner import CodeScanner
from localvulnai.scanners.web_scanner import WebScanner
from localvulnai.reporters.markdown import generate_markdown_report
from localvulnai.reporters.json_reporter import generate_json_report
from localvulnai.reporters.sarif import generate_sarif_report
from localvulnai.reporters.burp_export import generate_burp_friendly
from localvulnai.reporters.html_report import generate_html_report
from localvulnai.utils.summary import summarize
from localvulnai.utils.ignore import load_ignore_keys, filter_ignored, write_baseline
from localvulnai.utils.gitdiff import changed_files
from localvulnai.utils.deps import scan_requirements
from localvulnai.utils.webhook import notify_webhook
from localvulnai.config import load_scan_config
from localvulnai.models.finding import Finding

app = typer.Typer(
    name="localvulnai",
    help="Local AI-powered vulnerability scanner",
    add_completion=False,
)
console = Console()


@app.command()
def version():
    """Show version."""
    console.print(f"LocalVulnAI v{__version__}")


@app.command()
def check():
    """Check if Ollama is available."""
    client = OllamaClient()
    if client.is_available():
        console.print("[green]OK Ollama is available[/green]")
        console.print(f"  Model: {client.model}")
    else:
        console.print("[red]Ollama is not reachable[/red]")
        raise typer.Exit(1)


@app.command()
def baseline(
    path: str = typer.Option(".", "--path", "-p", help="Path to scan for baseline"),
    output: str = typer.Option(".localvulnai-ignore", "--output", "-o", help="Baseline file"),
):
    """Write current findings as ignore baseline."""
    findings = CodeScanner(path, use_ai=False).scan()
    findings.extend(scan_requirements(path))
    write_baseline(findings, output)
    console.print(f"[green]Wrote {len(findings)} fingerprints to {output}[/green]")


@app.command()
def scan(
    path: Optional[str] = typer.Option(None, "--path", "-p", help="Local path (comma-separated for multi)"),
    url: Optional[str] = typer.Option(None, "--url", "-u", help="URL (comma-separated for multi)"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Save report to file"),
    format: str = typer.Option("md", "--format", "-f", help="md|json|sarif|burp|html"),
    no_ai: bool = typer.Option(False, "--no-ai", help="Pattern-only"),
    deep: bool = typer.Option(False, "--deep", help="Playwright deep web scan"),
    config: Optional[str] = typer.Option(None, "--config", "-c", help=".localvulnai.yml path"),
    git_diff: bool = typer.Option(False, "--git-diff", help="Only scan files changed vs HEAD~1"),
    ignore_file: Optional[str] = typer.Option(None, "--ignore", help=".localvulnai-ignore path"),
    webhook: Optional[str] = typer.Option(None, "--webhook", help="Discord/Slack webhook URL"),
    lang: str = typer.Option("en", "--lang", help="Report language: en|bn"),
    deps: bool = typer.Option(True, "--deps/--no-deps", help="Scan requirements.txt heuristics"),
):
    """Scan code or websites for vulnerabilities."""
    if not path and not url and not git_diff:
        console.print("[red]Error:[/red] Provide --path, --url, or --git-diff")
        raise typer.Exit(1)
    if format not in ("md", "json", "sarif", "burp", "html"):
        console.print("[red]Error:[/red] format must be md|json|sarif|burp|html")
        raise typer.Exit(1)

    findings: List[Finding] = []
    targets: List[str] = []
    scan_cfg = load_scan_config(config)

    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console) as progress:
        task = progress.add_task("Scanning...", total=None)

        if git_diff:
            files = changed_files(".")
            progress.update(task, description=f"Git diff: {len(files)} files")
            for fp in files:
                findings.extend(CodeScanner(str(fp), use_ai=not no_ai, config=scan_cfg).scan())
            targets.append("git-diff")
            if deps:
                findings.extend(scan_requirements("."))

        if path:
            paths = [x.strip() for x in path.split(",") if x.strip()]
            for p in paths:
                progress.update(task, description=f"Code: {p}")
                findings.extend(CodeScanner(p, use_ai=not no_ai, config=scan_cfg).scan())
                if deps:
                    findings.extend(scan_requirements(p))
                targets.append(p)

        if url:
            urls = [x.strip() for x in url.split(",") if x.strip()]
            for u in urls:
                progress.update(task, description=f"Web: {u}")
                findings.extend(WebScanner(u, deep=deep).scan())
                targets.append(u)

    seen = set()
    unique = []
    for f in findings:
        key = (f.title.lower(), f.location)
        if key not in seen:
            seen.add(key)
            unique.append(f)
    findings = unique

    ignore_keys = load_ignore_keys(ignore_file)
    before = len(findings)
    findings = filter_ignored(findings, ignore_keys)
    ignored_n = before - len(findings)

    target = ", ".join(targets)
    summary = summarize(findings)
    c = summary["counts"]

    console.print()
    console.print(Panel(f"Scan completed for [cyan]{target}[/cyan]", title="LocalVulnAI"))
    console.print(
        f"Summary: {summary['total']} findings | risk {summary['risk_score']} ({summary['risk_level']}) | "
        f"crit={c['critical']} high={c['high']} med={c['medium']} low={c['low']} info={c['info']}"
        + (f" | ignored={ignored_n}" if ignored_n else "")
    )
    console.print()

    if not findings:
        console.print("[green]No issues found.[/green]")
    else:
        table = Table(title=f"Findings ({len(findings)})")
        table.add_column("Severity", style="bold", width=10)
        table.add_column("Title")
        table.add_column("Location")
        for f in findings:
            color = {"critical": "red", "high": "red", "medium": "yellow", "low": "blue", "info": "dim"}.get(
                f.severity.value, "white"
            )
            table.add_row(f"[{color}]{f.severity.value.upper()}[/{color}]", f.title, f.location)
        console.print(table)

    if format == "json":
        generate_json_report(findings, target, output)
    elif format == "sarif":
        generate_sarif_report(findings, target, output)
    elif format == "burp":
        generate_burp_friendly(findings, target, output)
    elif format == "html":
        generate_html_report(findings, target, output, lang=lang)
    else:
        generate_markdown_report(findings, target, output)

    if output:
        console.print(f"[green]Report saved:[/green] {output}")

    if webhook:
        ok = notify_webhook(webhook, findings, target)
        console.print("[green]Webhook sent[/green]" if ok else "[yellow]Webhook failed[/yellow]")


if __name__ == "__main__":
    app()
