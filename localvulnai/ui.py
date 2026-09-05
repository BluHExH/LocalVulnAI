"""Pretty terminal UI helpers for LocalVulnAI."""
from typing import List, Optional
from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.align import Align
from rich.rule import Rule
from rich.columns import Columns
from localvulnai.models.finding import Finding
from localvulnai import __version__

console = Console()

BANNER = r"""
[bold cyan]
  _                     _  __     __    _         _    ___
 | |                   | | \ \   / /   | |       | |  |_ _|
 | |     ___   ___ __ _| |  \ \ / /   _| |_ __   | |   | |
 | |    / _ \ / __/ _` | |   \ V / | | | | '_ \  | |   | |
 | |___| (_) | (_| (_| | |    | || |_| | | | | | | |___| |
 |______\___/ \___\__,_|_|    |_| \__,_|_|_| |_| |_____|_|
[/bold cyan]
"""

SEV_STYLE = {
    "critical": "bold white on dark_red",
    "high": "bold red",
    "medium": "bold yellow",
    "low": "bold blue",
    "info": "dim cyan",
}

SEV_ICON = {
    "critical": "🔥",
    "high": "🔴",
    "medium": "🟡",
    "low": "🔵",
    "info": "ℹ️ ",
}

RISK_STYLE = {
    "critical": "bold red",
    "high": "bold bright_red",
    "medium": "bold yellow",
    "low": "bold green",
    "clean": "bold bright_green",
}


def print_banner():
    console.print(Align.center(Text.from_markup(BANNER)))
    console.print(
        Align.center(
            Text.from_markup(
                f"[dim]v{__version__}[/dim]  [cyan]•[/cyan]  "
                "[dim]local AI vulnerability scanner[/dim]  [cyan]•[/cyan]  "
                "[dim]authorized use only[/dim]"
            )
        )
    )
    console.print()


def print_error(msg: str):
    console.print(
        Panel(
            f"[bold red]{msg}[/bold red]",
            title="[red]Error[/red]",
            border_style="red",
            padding=(0, 2),
        )
    )


def print_success(msg: str):
    console.print(
        Panel(
            f"[bold green]{msg}[/bold green]",
            border_style="green",
            padding=(0, 2),
        )
    )


def print_info(msg: str):
    console.print(f"[cyan]›[/cyan] {msg}")


def risk_bar(score: int, width: int = 24) -> Text:
    filled = int((score / 100) * width)
    empty = width - filled
    if score >= 40:
        color = "red"
    elif score >= 20:
        color = "yellow"
    elif score >= 8:
        color = "blue"
    else:
        color = "green"
    bar = Text()
    bar.append("█" * filled, style=color)
    bar.append("░" * empty, style="dim")
    bar.append(f"  {score}/100", style=f"bold {color}")
    return bar


def print_scan_header(target: str, mode: str = ""):
    body = Text()
    body.append("🎯  Target  ", style="bold")
    body.append(target, style="cyan")
    if mode:
        body.append("\n⚙️   Mode    ", style="bold")
        body.append(mode, style="dim")
    console.print(
        Panel(
            body,
            title="[bold cyan]Scan[/bold cyan]",
            border_style="cyan",
            padding=(0, 2),
        )
    )


def print_summary(summary: dict, ignored: int = 0):
    c = summary["counts"]
    level = summary["risk_level"]
    style = RISK_STYLE.get(level, "white")

    cards = []
    for label, key, sty in [
        ("CRITICAL", "critical", "red"),
        ("HIGH", "high", "red"),
        ("MEDIUM", "medium", "yellow"),
        ("LOW", "low", "blue"),
        ("INFO", "info", "cyan"),
    ]:
        n = c.get(key, 0)
        cards.append(
            Panel(
                Align.center(Text(str(n), style=f"bold {sty}")),
                title=f"[{sty}]{label}[/{sty}]",
                border_style=sty if n else "dim",
                width=14,
                padding=(0, 0),
            )
        )

    console.print()
    console.print(Rule("[bold]Summary[/bold]", style="cyan"))
    console.print()
    console.print(Columns(cards, equal=True, expand=False))
    console.print()

    risk_line = Text()
    risk_line.append("Risk level  ", style="bold")
    risk_line.append(level.upper(), style=style)
    console.print(risk_line)
    console.print(Text("Risk score  ", style="bold"), risk_bar(summary["risk_score"]))
    console.print(
        Text.from_markup(
            f"[bold]Findings[/bold]    [white]{summary['total']}[/white]"
            + (f"  [dim]({ignored} ignored)[/dim]" if ignored else "")
        )
    )
    console.print()


def print_findings_table(findings: List[Finding]):
    if not findings:
        console.print(
            Panel(
                Align.center("[bold green]✓  No issues found — looking clean[/bold green]"),
                border_style="green",
                padding=(1, 2),
            )
        )
        return

    table = Table(
        title="[bold]Findings[/bold]",
        show_header=True,
        header_style="bold cyan",
        border_style="dim",
        row_styles=["none", "dim"],
        expand=True,
    )
    table.add_column("", width=2)
    table.add_column("Severity", width=12)
    table.add_column("Issue", ratio=2)
    table.add_column("Location", ratio=2, style="dim")

    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    sorted_f = sorted(findings, key=lambda x: order.get(x.severity.value, 5))

    for f in sorted_f:
        sev = f.severity.value
        icon = SEV_ICON.get(sev, "•")
        table.add_row(
            icon,
            Text(sev.upper(), style=SEV_STYLE.get(sev, "white")),
            f.title,
            f.location,
        )

    console.print(table)
    console.print()


def print_finding_details(findings: List[Finding], limit: int = 5):
    if not findings:
        return
    console.print(Rule("[bold]Details[/bold]", style="cyan"))
    console.print()
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    sorted_f = sorted(findings, key=lambda x: order.get(x.severity.value, 5))

    for i, f in enumerate(sorted_f[:limit], 1):
        sev = f.severity.value
        icon = SEV_ICON.get(sev, "•")
        header = Text()
        header.append(f"{icon} ")
        header.append(f.title, style="bold")
        header.append("  ")
        header.append(f" {sev.upper()} ", style=SEV_STYLE.get(sev, "white"))

        lines = [header, Text()]
        lines.append(Text.from_markup(f"[dim]📍[/dim]  [cyan]{f.location}[/cyan]"))
        lines.append(Text())
        lines.append(Text(f.description[:300] + ("…" if len(f.description) > 300 else "")))
        if f.recommendation:
            lines.append(Text())
            lines.append(Text.from_markup(f"[green]💡 Fix:[/green] {f.recommendation}"))
        if f.cwe:
            lines.append(Text.from_markup(f"[dim]CWE: {f.cwe}[/dim]"))

        console.print(
            Panel(
                Group(*lines),
                border_style="dim",
                padding=(0, 1),
                title=f"[dim]#{i}[/dim]",
                title_align="left",
            )
        )
    if len(findings) > limit:
        console.print(f"[dim]  … and {len(findings) - limit} more (see report file)[/dim]")
    console.print()


def print_footer(output: Optional[str] = None):
    console.print(Rule(style="dim"))
    tips = Text.from_markup(
        "[dim]Tips:[/dim]  "
        "[cyan]-o report.html -f html[/cyan]  ·  "
        "[cyan]--git-diff[/cyan]  ·  "
        "[cyan]baseline[/cyan]  ·  "
        "[cyan]--deep[/cyan]"
    )
    console.print(Align.center(tips))
    if output:
        console.print(
            Align.center(Text.from_markup(f"[green]✓ Report saved →[/green] [bold]{output}[/bold]"))
        )
    console.print()
