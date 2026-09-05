"""Pretty terminal UI helpers for LocalVulnAI."""
from typing import List, Optional, Dict, Any
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

BANNER = (
    "[bold bright_cyan]"
    "\n  ╔══════════════════════════════════════════════════╗"
    "\n  ║   L O C A L V U L N A I                          ║"
    "\n  ║   AI-powered · local · authorized testing only   ║"
    "\n  ╚══════════════════════════════════════════════════╝"
    "\n[/bold bright_cyan]"
)

SEV_STYLE = {
    "critical": "bold white on dark_red",
    "high": "bold bright_red",
    "medium": "bold bright_yellow",
    "low": "bold bright_blue",
    "info": "dim cyan",
}

SEV_ICON = {
    "critical": "🔥",
    "high": "🔴",
    "medium": "🟡",
    "low": "🔵",
    "info": "ℹ️ ",
}

BORDER = {
    "critical": "dark_red",
    "high": "red",
    "medium": "yellow",
    "low": "blue",
    "info": "cyan",
    "clean": "green",
}


def print_banner():
    console.print(Align.center(Text.from_markup(BANNER)))
    console.print(
        Align.center(
            Text.from_markup(
                f"[bold white]v{__version__}[/bold white]  [bright_cyan]◆[/bright_cyan]  "
                "[white]Local AI Vulnerability Scanner[/white]  [bright_cyan]◆[/bright_cyan]  "
                "[dim]authorized use only[/dim]"
            )
        )
    )
    console.print(Align.center(Text.from_markup("[dim]──────────────────────────────────────────────[/dim]")))
    console.print()


def print_error(msg: str):
    console.print(
        Panel(
            Text.from_markup(f"[bold red]{msg}[/bold red]"),
            title="[bold red] ✕ ERROR [/bold red]",
            border_style="red",
            padding=(0, 2),
        )
    )


def print_success(msg: str):
    console.print(
        Panel(
            Text.from_markup(f"[bold green]{msg}[/bold green]"),
            title="[bold green] ✓ DONE [/bold green]",
            border_style="green",
            padding=(0, 2),
        )
    )


def print_info(msg: str):
    console.print(Text.from_markup(f"[bright_cyan] ›[/bright_cyan] {msg}"))


def risk_bar(score: int, width: int = 28) -> Text:
    score = max(0, min(100, int(score)))
    filled = int((score / 100) * width)
    empty = width - filled
    if score >= 40:
        color = "bright_red"
    elif score >= 20:
        color = "bright_yellow"
    elif score >= 8:
        color = "bright_blue"
    else:
        color = "bright_green"
    bar = Text()
    bar.append("━" * filled, style=f"bold {color}")
    bar.append("━" * empty, style="dim")
    bar.append(f"  {score}", style=f"bold {color}")
    return bar


def _stat_panel(label: str, value: str, style: str) -> Panel:
    body = Text()
    body.append(f"{value}\n", style=f"bold {style}")
    body.append(label, style="dim")
    return Panel(Align.center(body), border_style=style, width=16, padding=(0, 1))


def print_summary(summary: Dict[str, Any], ignored: int = 0, target: str = ""):
    c = summary.get("counts", {})
    level = summary.get("risk_level", "clean")
    score = summary.get("risk_score", 0)
    total = summary.get("total", 0)

    console.print()
    if target:
        console.print(
            Panel(
                Text.from_markup(f"[bold white]Target[/bold white]  [bright_cyan]{target}[/bright_cyan]"),
                border_style="bright_cyan",
                padding=(0, 2),
            )
        )

    gauge = Text()
    gauge.append("RISK  ", style="bold white")
    gauge.append(risk_bar(score))
    gauge.append(
        f"  [{level.upper()}]",
        style=SEV_STYLE.get(level, "white") if level != "clean" else "bold bright_green",
    )

    console.print(
        Panel(
            Align.center(gauge),
            title="[bold] Security Score [/bold]",
            border_style=BORDER.get(level, "cyan"),
            padding=(0, 1),
        )
    )

    cards = Columns(
        [
            _stat_panel("TOTAL", str(total), "white"),
            _stat_panel("CRITICAL", str(c.get("critical", 0)), "bright_red"),
            _stat_panel("HIGH", str(c.get("high", 0)), "red"),
            _stat_panel("MEDIUM", str(c.get("medium", 0)), "yellow"),
            _stat_panel("LOW", str(c.get("low", 0)), "blue"),
            _stat_panel("INFO", str(c.get("info", 0)), "cyan"),
        ],
        equal=True,
        expand=True,
    )
    console.print(cards)

    if ignored:
        console.print(Align.center(Text.from_markup(f"[dim]({ignored} findings hidden by baseline)[/dim]")))
    console.print()


def print_findings_table(findings: List[Finding]):
    if not findings:
        console.print(
            Panel(
                Align.center(
                    Text.from_markup("[bold bright_green]✓ No issues found — looking clean[/bold bright_green]")
                ),
                border_style="green",
                padding=(1, 2),
            )
        )
        console.print()
        return

    table = Table(
        title="[bold]Findings[/bold]",
        title_style="bold bright_cyan",
        border_style="bright_cyan",
        header_style="bold white",
        show_lines=True,
        expand=True,
        pad_edge=True,
    )
    table.add_column("", width=3, justify="center")
    table.add_column("Severity", width=12)
    table.add_column("Issue", ratio=2)
    table.add_column("Location", ratio=2, style="cyan")

    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    sorted_f = sorted(findings, key=lambda x: order.get(x.severity.value, 5))

    for f in sorted_f:
        sev = f.severity.value
        table.add_row(
            SEV_ICON.get(sev, "•"),
            Text(f" {sev.upper()} ", style=SEV_STYLE.get(sev, "white")),
            f.title,
            f.location,
        )

    console.print(table)
    console.print()


def print_finding_details(findings: List[Finding], limit: int = 6):
    if not findings:
        return
    console.print(Rule("[bold bright_cyan]Issue details[/bold bright_cyan]", style="bright_cyan"))
    console.print()
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    sorted_f = sorted(findings, key=lambda x: order.get(x.severity.value, 5))

    for i, f in enumerate(sorted_f[:limit], 1):
        sev = f.severity.value
        icon = SEV_ICON.get(sev, "•")
        header = Text()
        header.append(f"{icon} ")
        header.append(f.title, style="bold white")
        header.append("  ")
        header.append(f" {sev.upper()} ", style=SEV_STYLE.get(sev, "white"))

        body_parts = [header, Text("")]
        body_parts.append(Text.from_markup(f"[dim]📍[/dim]  [bright_cyan]{f.location}[/bright_cyan]"))
        body_parts.append(Text(""))
        desc = f.description[:320] + ("…" if len(f.description) > 320 else "")
        body_parts.append(Text(desc, style="white"))
        if f.recommendation:
            body_parts.append(Text(""))
            body_parts.append(Text.from_markup(f"[bright_green]💡 Fix[/bright_green]  {f.recommendation}"))
        if f.cwe:
            body_parts.append(Text.from_markup(f"[dim]{f.cwe}[/dim]"))

        console.print(
            Panel(
                Group(*body_parts),
                border_style=BORDER.get(sev, "dim"),
                padding=(0, 1),
                title=f"[bold]#{i}[/bold]",
                title_align="left",
            )
        )

    if len(findings) > limit:
        console.print(
            Align.center(
                Text.from_markup(
                    f"[dim]… and {len(findings) - limit} more — open the report file for full list[/dim]"
                )
            )
        )
    console.print()


def print_footer(output: Optional[str] = None):
    console.print(Rule(style="dim"))
    console.print(
        Align.center(
            Text.from_markup(
                "[dim]Next:[/dim]  "
                "[bright_cyan]-o report.html -f html[/bright_cyan]  ·  "
                "[bright_cyan]--git-diff[/bright_cyan]  ·  "
                "[bright_cyan]baseline[/bright_cyan]  ·  "
                "[bright_cyan]--deep[/bright_cyan]"
            )
        )
    )
    if output:
        console.print(
            Align.center(
                Text.from_markup(
                    f"[bright_green]✓ Report saved[/bright_green]  →  [bold white]{output}[/bold white]"
                )
            )
        )
    console.print(Align.center(Text.from_markup("[dim]github.com/BluHExH/LocalVulnAI[/dim]")))
    console.print()
