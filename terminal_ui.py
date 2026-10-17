"""ASCII branding, live request progress and evidence tables for the CLI."""

from collections import Counter
from pathlib import Path

from rich import box
from rich.align import Align
from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, Progress, TaskProgressColumn, TextColumn, TimeElapsedColumn
from rich.table import Table
from rich.text import Text

from engine import VERSION
from runner import csv_text, planned_requests, run_scan

COLORS = {
    "block_signal": "#f7b955",
    "no_block_signal": "#a7b0bd",
    "redirect": "#a69af8",
    "ambiguous": "#a7b0bd",
    "rate_limited": "#f58174",
    "server_error": "#f58174",
    "transport_error": "#f58174",
    "skipped": "#8795a7",
}
LABELS = {
    "same_sample": "same sample",
    "different_sample": "different sample",
    "baseline_inconclusive": "control inconclusive",
    "incomplete_sample": "incomplete sample",
    "unavailable": "control unavailable",
    "not_collected": "no control",
    "control": "neutral control",
}


BANNER = r"""    ______________  _____________________  ____  __  ___
   / ____/  _/ __ \/ ____/ ___/_  __/ __ \/ __ \/  |/  /
  / /_   / // /_/ / __/  \__ \ / / / / / / /_/ / /|_/ /
 / __/ _/ // _, _/ /___ ___/ // / / /_/ / _, _/ /  / /
/_/   /___/_/ |_/_____//____//_/  \____/_/ |_/_/  /_/"""


def print_banner(console):
    art = Text()
    for line, color in zip(BANNER.splitlines(), ("#ff825b", "#fb9560", "#f5a564", "#efb36b", "#e8c079")):
        art.append(line + "\n", style="bold " + color)
    art.rstrip()
    console.print(
        Panel(
            Align.center(art) if console.width >= 76 else Text("F I R E S T O R M", style="bold #ff825b"),
            title=f"FIRESTORM / {VERSION}",
            title_align="left",
            subtitle="HTTP RESPONSE OBSERVATORY / AUTHORIZED LABS",
            subtitle_align="left",
            border_style="#ff825b",
            padding=(1, 2),
        )
    )


def report(console, rows, csv_path=None):
    probes = [row for row in rows if row.get("phase") != "baseline"]
    controls = [row for row in rows if row.get("phase") == "baseline"]
    counts = Counter(row["result"] for row in probes)
    metrics = Table.grid(expand=True)
    for _ in range(4):
        metrics.add_column(ratio=1)
    metrics.add_row(
        "[bold]PROBE ROWS[/]",
        "[bold #f7b955]BLOCK SIGNALS[/]",
        "[bold]SAME AS CONTROL[/]",
        "[bold]CONTROLS[/]",
    )
    metrics.add_row(
        str(len(probes)),
        str(counts["block_signal"]),
        str(sum(row.get("comparison") == "same_sample" for row in probes)),
        str(len(controls)),
    )
    console.print(Panel(metrics, border_style="#384352", padding=(1, 2)))
    table = Table(box=box.SIMPLE, expand=True, padding=(0, 1), header_style="bold #93a2b7")
    for title in ("PHASE / PROBE", "DELIVERY", "HTTP", "OBSERVATION", "BASELINE"):
        table.add_column(title, no_wrap=title in {"HTTP", "DELIVERY"})
    for row in rows:
        label = "control / neutral" if row.get("phase") == "baseline" else row["name"]
        table.add_row(
            Text(label),
            Text(str(row["method"] or "—")),
            str(row["status"] or "—"),
            Text(row["result"], style=COLORS[row["result"]]),
            LABELS.get(row.get("comparison"), "no control"),
        )
    console.print(table)
    console.print(
        Panel(
            "[bold]UNCONFIRMED[/]  HTTP status, denial text and baseline differences are observations.\n"
            "Confirmed WAF blocks: not measured. Confirmed exploits: not measured.\n"
            "No effectiveness score: HTTP observations cannot measure WAF strength.",
            title="EVIDENCE BOUNDARY",
            title_align="left",
            border_style="#384352",
        )
    )
    if csv_path:
        Path(csv_path).write_text(csv_text(rows), encoding="utf-8", newline="")
        console.print("[dim]CSV saved:[/]", Text(str(csv_path)))


def run_terminal(config, corpus, csv_path=None, plain=False, screenshot=None):
    console = Console(record=True, color_system=None if plain else "auto", highlight=False)
    print_banner(console)
    console.print("[bold]Endpoint[/]", Text(config.url))
    console.print(
        f"[dim]Budget {config.max_requests} · Interval {config.interval}s · Timeout {config.timeout}s · Redirects off[/]"
    )
    console.print(
        "[dim]Neutral controls share the request budget. Every observation remains unconfirmed.[/]\n"
    )
    with Progress(
        TextColumn("[bold]Observing[/]"),
        BarColumn(complete_style="#ff825b"),
        TaskProgressColumn(),
        TextColumn("{task.completed:.0f}/{task.total:.0f} requests"),
        TimeElapsedColumn(),
        console=console,
        transient=True,
        disable=not console.is_terminal,
    ) as progress:
        task = progress.add_task(
            "requests", total=min(config.max_requests, planned_requests(corpus, config.baseline))
        )

        def update(row, requests):
            progress.update(task, completed=requests)

        outcome = run_scan(config, corpus, on_row=update)
    console.print(progress.get_renderable())
    reason = outcome["stop_reason"].replace("_", " ").upper()
    console.print(
        Text(
            f"{reason}  /  {outcome['requests']} requests  /  {outcome['elapsed_seconds']:.2f}s",
            style="bold #f7b955",
        )
    )
    if outcome["stop_reason"] != "completed":
        console.print("[dim]Selected inputs or deliveries may remain untested.[/]")
    report(console, outcome["rows"], csv_path)
    if screenshot:
        console.save_svg(screenshot, title="Firestorm · actual local fixture run")
    return outcome
