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
    no_ai: bool = typer.Option(False, "--no-ai", help="Disable AI analysis (pattern-only, faster)"),
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
            use_ai = not no_ai
            if use_ai:
                client = OllamaClient()
                if not client.is_available():
                    console.print("[yellow]⚠ Ollama not available — falling back to pattern-only scan[/yellow]")
                    use_ai = False
            scanner = CodeScanner(path, use_ai=use_ai)
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

        # Show short description of first few findings
        console.print()
        for f in findings[:5]:
            console.print(f"[bold]{f.title}[/bold]")
            console.print(f"  {f.description[:200]}{'...' if len(f.description) > 200 else ''}")
            if f.recommendation:
                console.print(f"  [green]Fix:[/green] {f.recommendation}")
            console.print()

    # Report
    generate_markdown_report(findings, target or "", output)
    if output:
        console.print(f"[green]Report saved to:[/green] {output}")
    else:
        console.print("[dim]Tip: use --output report.md to save a full Markdown report[/dim]")


if __name__ == "__main__":
    app()
