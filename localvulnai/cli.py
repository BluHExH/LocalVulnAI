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
        console.print("[green]✓ Ollama is available[/green]")
        console.print(f"  Model: {client.model}")
    else:
        console.print("[red]✗ Ollama is not reachable[/red]")
        console.print("  Make sure Ollama is running: https://ollama.com")
        raise typer.Exit(1)


@app.command()
def scan(
    path: Optional[str] = typer.Option(None, "--path", "-p", help="Local path to scan"),
    url: Optional[str] = typer.Option(None, "--url", "-u", help="URL to scan (authorized only)"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Save report to file"),
):
    """Scan code or a website for common vulnerabilities."""
    if not path and not url:
        console.print("[red]Error:[/red] Provide either --path or --url")
        raise typer.Exit(1)

    if path and url:
        console.print("[red]Error:[/red] Use either --path or --url, not both")
        raise typer.Exit(1)

    findings = []
    target = path or url

    with console.status("[bold green]Scanning..."):
        if path:
            scanner = CodeScanner(path)
            findings = scanner.scan()
        else:
            scanner = WebScanner(url)
            findings = scanner.scan()

    # Display results
    console.print()
    console.print(Panel(f"Scan completed for [cyan]{target}[/cyan]", title="LocalVulnAI"))

    if not findings:
        console.print("[green]No issues found.[/green]")
    else:
        table = Table(title="Findings")
        table.add_column("Severity", style="bold")
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
            table.add_row(f"[{color}]{f.severity.value.upper()}[/{color}]", f.title, f.location)

        console.print(table)

    # Report
    report = generate_markdown_report(findings, target or "", output)
    if output:
        console.print(f"\n[green]Report saved to:[/green] {output}")
    else:
        console.print("\n[dim]Use --output report.md to save a full report[/dim]")


if __name__ == "__main__":
    app()
