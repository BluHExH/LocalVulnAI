from typing import Optional
import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from localvulnai import __version__
from localvulnai.ai.ollama_client import OllamaClient
from localvulnai.scanners.code_scanner import CodeScanner
from localvulnai.scanners.web_scanner import WebScanner
from localvulnai.reporters.markdown import generate_markdown_report
from localvulnai.reporters.json_reporter import generate_json_report
from localvulnai.reporters.sarif import generate_sarif_report
from localvulnai.reporters.burp_export import generate_burp_friendly
from localvulnai.utils.summary import summarize
from localvulnai.config import load_scan_config

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
        console.print("  Make sure Ollama is running: https://ollama.com")
        raise typer.Exit(1)


@app.command()
def scan(
    path: Optional[str] = typer.Option(None, "--path", "-p", help="Local path to scan"),
    url: Optional[str] = typer.Option(None, "--url", "-u", help="URL to scan (authorized only)"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Save report to file"),
    format: str = typer.Option("md", "--format", "-f", help="Report format: md | json | sarif | burp"),
    no_ai: bool = typer.Option(False, "--no-ai", help="Disable AI analysis (pattern-only)"),
    deep: bool = typer.Option(False, "--deep", help="Deeper web scan with Playwright"),
    config: Optional[str] = typer.Option(None, "--config", "-c", help="Path to .localvulnai.yml"),
):
    """Scan code or a website for common vulnerabilities."""
    if not path and not url:
        console.print("[red]Error:[/red] Provide either --path or --url")
        raise typer.Exit(1)
    if path and url:
        console.print("[red]Error:[/red] Use either --path or --url, not both")
        raise typer.Exit(1)
    if format not in ("md", "json", "sarif", "burp"):
        console.print("[red]Error:[/red] --format must be md, json, sarif, or burp")
        raise typer.Exit(1)

    findings = []
    target = path or url
    scan_cfg = load_scan_config(config)

    with console.status("[bold green]Scanning..."):
        if path:
            use_ai = not no_ai
            client = OllamaClient()
            if use_ai and not client.is_available():
                console.print("[yellow]Ollama not available - pattern-only scan[/yellow]")
                use_ai = False
            scanner = CodeScanner(path, use_ai=use_ai, config=scan_cfg)
            findings = scanner.scan()
        else:
            scanner = WebScanner(url, deep=deep)
            findings = scanner.scan()

    summary = summarize(findings)
    c = summary["counts"]

    console.print()
    console.print(Panel(f"Scan completed for [cyan]{target}[/cyan]", title="LocalVulnAI"))
    msg = (
        f"Summary: {summary['total']} findings | "
        f"risk {summary['risk_score']} ({summary['risk_level']}) | "
        f"crit={c['critical']} high={c['high']} med={c['medium']} low={c['low']} info={c['info']}"
    )
    console.print(msg)
    console.print()

    if not findings:
        console.print("[green]No issues found.[/green]")
    else:
        table = Table(title=f"Findings ({len(findings)})")
        table.add_column("Severity", style="bold", width=10)
        table.add_column("Title")
        table.add_column("Location")
        for f in findings:
            color = {
                "critical": "red",
                "high": "red",
                "medium": "yellow",
                "low": "blue",
                "info": "dim",
            }.get(f.severity.value, "white")
            table.add_row(
                f"[{color}]{f.severity.value.upper()}[/{color}]",
                f.title,
                f.location,
            )
        console.print(table)
        console.print()
        for f in findings[:6]:
            console.print(f"[bold]{f.title}[/bold]")
            desc = f.description[:220] + ("..." if len(f.description) > 220 else "")
            console.print(f"  {desc}")
            if f.recommendation:
                console.print(f"  [green]Fix:[/green] {f.recommendation}")
            console.print()

    if format == "json":
        generate_json_report(findings, target or "", output)
    elif format == "sarif":
        generate_sarif_report(findings, target or "", output)
    elif format == "burp":
        generate_burp_friendly(findings, target or "", output)
    else:
        generate_markdown_report(findings, target or "", output)

    if output:
        console.print(f"[green]Report saved to:[/green] {output}")
    else:
        console.print("[dim]Tip: -o report.md | -f json | -f sarif | -f burp[/dim]")


if __name__ == "__main__":
    app()
