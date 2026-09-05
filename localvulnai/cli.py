from typing import Optional, List
import typer
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.console import Console

from localvulnai import __version__
from localvulnai import ui
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
    rich_markup_mode="rich",
)
console = Console()


@app.callback(invoke_without_command=True)
def main(ctx: typer.Context):
    if ctx.invoked_subcommand is None:
        ui.print_banner()
        console.print(
            "  [bold]Commands:[/bold]  "
            "[cyan]scan[/cyan]  ·  [cyan]check[/cyan]  ·  [cyan]baseline[/cyan]  ·  [cyan]version[/cyan]"
        )
        console.print(
            "  [dim]Example:[/dim]  [white]python -m localvulnai scan --path ./src --no-ai[/white]"
        )
        console.print()


@app.command()
def version():
    """Show version."""
    ui.print_banner()
    console.print(f"  [bold cyan]LocalVulnAI[/bold cyan] [white]v{__version__}[/white]")
    console.print()


@app.command()
def check():
    """Check if Ollama is available."""
    ui.print_banner()
    client = OllamaClient()
    if client.is_available():
        ui.print_success(f"Ollama is online  ·  model: [bold]{client.model}[/bold]")
    else:
        ui.print_error("Ollama is not reachable — start it or use --no-ai")
        raise typer.Exit(1)


@app.command()
def baseline(
    path: str = typer.Option(".", "--path", "-p", help="Path to scan for baseline"),
    output: str = typer.Option(".localvulnai-ignore", "--output", "-o", help="Baseline file"),
):
    """Write current findings as ignore baseline."""
    ui.print_banner()
    with console.status("[cyan]Building baseline…[/cyan]"):
        findings = CodeScanner(path, use_ai=False).scan()
        findings.extend(scan_requirements(path))
        write_baseline(findings, output)
    ui.print_success(f"Saved [bold]{len(findings)}[/bold] fingerprints → [cyan]{output}[/cyan]")


@app.command()
def scan(
    path: Optional[str] = typer.Option(None, "--path", "-p", help="Local path (comma-separated)"),
    url: Optional[str] = typer.Option(None, "--url", "-u", help="URL (comma-separated)"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Save report"),
    format: str = typer.Option("md", "--format", "-f", help="md|json|sarif|burp|html"),
    no_ai: bool = typer.Option(False, "--no-ai", help="Pattern-only"),
    deep: bool = typer.Option(False, "--deep", help="Playwright deep web"),
    config: Optional[str] = typer.Option(None, "--config", "-c", help=".localvulnai.yml"),
    git_diff: bool = typer.Option(False, "--git-diff", help="Only changed files vs HEAD~1"),
    ignore_file: Optional[str] = typer.Option(None, "--ignore", help=".localvulnai-ignore"),
    webhook: Optional[str] = typer.Option(None, "--webhook", help="Discord/Slack webhook"),
    lang: str = typer.Option("en", "--lang", help="en|bn for HTML"),
    deps: bool = typer.Option(True, "--deps/--no-deps", help="Scan requirements.txt"),
):
    """Scan code or websites for vulnerabilities."""
    ui.print_banner()
    if not path and not url and not git_diff:
        ui.print_error("Provide --path, --url, or --git-diff")
        raise typer.Exit(1)
    if format not in ("md", "json", "sarif", "burp", "html"):
        ui.print_error("format must be md | json | sarif | burp | html")
        raise typer.Exit(1)

    findings: List[Finding] = []
    targets: List[str] = []
    scan_cfg = load_scan_config(config)

    with Progress(
        SpinnerColumn(style="cyan"),
        TextColumn("[cyan]{task.description}"),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task("Starting…", total=None)

        if git_diff:
            files = changed_files(".")
            progress.update(task, description=f"Git diff · {len(files)} files")
            for fp in files:
                findings.extend(CodeScanner(str(fp), use_ai=not no_ai, config=scan_cfg).scan())
            targets.append("git-diff")
            if deps:
                findings.extend(scan_requirements("."))

        if path:
            for p in [x.strip() for x in path.split(",") if x.strip()]:
                progress.update(task, description=f"Scanning code · {p}")
                findings.extend(CodeScanner(p, use_ai=not no_ai, config=scan_cfg).scan())
                if deps:
                    findings.extend(scan_requirements(p))
                targets.append(p)

        if url:
            for u in [x.strip() for x in url.split(",") if x.strip()]:
                progress.update(task, description=f"Scanning web · {u}")
                findings.extend(WebScanner(u, deep=deep).scan())
                targets.append(u)

        progress.update(task, description="Deduplicating…")

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

    ui.print_summary(summary, ignored=ignored_n, target=target)
    ui.print_findings_table(findings)
    ui.print_finding_details(findings, limit=5)

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

    if webhook:
        ok = notify_webhook(webhook, findings, target)
        ui.print_info("Webhook delivered" if ok else "[yellow]Webhook failed[/yellow]")

    ui.print_footer(output)


if __name__ == "__main__":
    app()
