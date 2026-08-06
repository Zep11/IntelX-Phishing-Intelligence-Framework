# uiux.py
# Central UI/UX module for the Phishing URL Analyzer

import os
import sys
import time
from typing import Any, Callable, Optional
from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text


# Shared console object.
# Import this in main.py when you need direct Rich printing:
# from uiux import console
console = Console()


# ============================================================
# TERMINAL UTILITIES
# ============================================================

def clear_screen() -> None:
    """
    Clear the entire terminal screen.

    Windows:
        cls

    Linux/macOS:
        clear
    """
    os.system("cls" if os.name == "nt" else "clear")


def clear_previous_lines(number_of_lines: int = 1) -> None:
    """
    Move the terminal cursor upward and clear previous lines.

    This is used for temporary prompts that should disappear
    after the user provides an answer.

    Works best in:
    - Windows Terminal
    - PowerShell
    - VS Code terminal
    - Linux/macOS terminals
    """
    if number_of_lines <= 0:
        return

    for _ in range(number_of_lines):
        sys.stdout.write("\033[F")
        sys.stdout.write("\033[2K")

    sys.stdout.flush()


def pause(seconds: float = 0.4) -> None:
    """Small reusable delay for UI transitions."""
    time.sleep(seconds)



TYPE_SPEED_FAST = 0.012
TYPE_SPEED_NORMAL = 0.025
TYPE_SPEED_SLOW = 0.04
LINE_PAUSE = 0.20

# ============================================================
# TYPEWRITER TEXT
# ============================================================

def type_text(
    text: str,
    delay: float = TYPE_SPEED_NORMAL,
    style: Optional[str] = None,
    end: str = "\n",
) -> None:
    """
    Print text one character at a time.

    Usethis mainly for permanent headings and final results.

    Smaller delay:
        Faster animation

    Recommended:
        Heading: 0.008
        Normal text: 0.004–0.006
    """
    for character in str(text):
        console.print(
            Text(character, style=style),
            end="",
            soft_wrap=True,
        )
        time.sleep(delay)

    console.print(end=end)

def type_label_value(
    label: str,
    value,
    label_width: int = 14,
    delay: float = TYPE_SPEED_FAST,
):
    """
    Type a label and value using direct Rich styles.
    No custom theme is required.
    """

    if value in [None, ""]:
        value = "Not Present"

    padded_label = f"{label:<{label_width}}"

    # Label in grey
    for character in padded_label:
        console.print(
            character,
            style="bold grey70",
            end=""
        )
        time.sleep(delay)

    # Value in white
    for character in str(value):
        console.print(
            character,
            style="white",
            end=""
        )
        time.sleep(delay)

    console.print()

def show_parsed_url_animated(parsed_data):
    """
    Display parsed URL information permanently
    with a line-by-line typing animation.
    """

    show_section("Parsed URL Information")

    fields = [
        ("Scheme", parsed_data.get("scheme")),
        ("Domain", parsed_data.get("domain")),
        ("Hostname", parsed_data.get("hostname")),
        ("Subdomain", parsed_data.get("subdomain")),
        ("Port", parsed_data.get("port")),
        ("Path", parsed_data.get("path")),
        ("Query", parsed_data.get("query")),
    ]

    for label, value in fields:
        type_label_value(
            label,
            value,
            label_width=14,
            delay=TYPE_SPEED_FAST,
        )

        time.sleep(0.15) 

def type_lines(
    lines: list[str],
    delay: float = TYPE_SPEED_NORMAL,
    line_delay: float = 0.20,
    style: Optional[str] = None,
) -> None:
    """Type several permanent lines one after another."""
    for line in lines:
        type_text(line, delay=delay, style=style)
        time.sleep(line_delay)


# ============================================================
# ASCII BANNER
# ============================================================

def show_banner() -> None:
    """Display the permanent startup banner."""

    banner = r"""
██╗███╗   ██╗████████╗███████╗██╗     ██╗  ██╗
██║████╗  ██║╚══██╔══╝██╔════╝██║     ╚██╗██╔╝
██║██╔██╗ ██║   ██║   █████╗  ██║      ╚███╔╝
██║██║╚██╗██║   ██║   ██╔══╝  ██║      ██╔██╗
██║██║ ╚████║   ██║   ███████╗███████╗██╔╝ ██╗
╚═╝╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚══════╝╚═╝  ╚═╝

───────────────────────────────────────────────────────────────
    Automated Multi-Source Threat Intelligence Platform
───────────────────────────────────────────────────────────────

  ◉ Static URL Analysis
  ◉ Dynamic Threat Intelligence
  ◉ IOC Correlation Engine
  ◉ Automated Incident Reporting

    INVESTIGATE • ANALYZE • CORRELATE • DEFEND
───────────────────────────────────────────────────────────────
"""

    content = Text()
    content.append(banner, style="bold white")
    content.append(
        "\nVersion 1.0",
        style="dim",
    )
    content.append(
        "\nAuthor: @Shubrajit_Dey",
        style="dim",
    )
    console.print(content)
    console.print()



# ============================================================
# TEMPORARY INPUT AND API PROMPTS
# ============================================================

def animated_input(
    message: str,
    delay: float = TYPE_SPEED_NORMAL,
    clear_after: bool = False,
) -> str:
    """
    Display a typewriter-style prompt and collect user input.

    When clear_after=True, the prompt and answer are removed.
    """
    type_text(message, delay=delay, style="bold cyan", end=" ")

    answer = console.input("[bold white]> [/bold white]").strip()

    if clear_after:
        # Normally clears the typed prompt line and answer line.
        clear_previous_lines(2)

    return answer

# PARSED URL DISPLAY 


def ask_yes_no(
    message: str,
    clear_after: bool = True,
) -> bool:
    """
    Ask a temporary Yes/No question.

    Accepts:
        Y, YES, N, NO
    """
    while True:
        type_text(
            message,
            delay=TYPE_SPEED_NORMAL,
            style="bold yellow",
            end=" ",
        )

        answer = console.input("[bold white]> [/bold white]").strip().lower()

        if clear_after:
            clear_previous_lines(2)

        if answer in {"y", "yes"}:
            return True

        if answer in {"n", "no"}:
            return False

        type_text(
            "Please enter Y or N.",
            delay=TYPE_SPEED_FAST,
            style="red",
        )
        time.sleep(0.6)

        if clear_after:
            clear_previous_lines(1)


def ask_api_key(provider_name: str) -> Optional[str]:
    """
    Ask whether the user wants to configure a missing API key.

    The temporary prompts disappear after the user responds.

    Returns:
        API key string, or None
    """
    wants_key = ask_yes_no(
        f"No {provider_name} API key is configured. "
        "Would you like to add one for better threat intelligence? (Y/N)"
    )

    if not wants_key:
        return None

    type_text(
        f"Enter the {provider_name} API key:",
        delay=TYPE_SPEED_NORMAL,
        style="bold cyan",
        end=" ",
    )

    api_key = console.input("[bold white]> [/bold white]").strip()

    # Clear API-entry prompt and entered key from the screen.
    clear_previous_lines(2)

    return api_key or None


def get_target_url() -> str:
    """Collect the URL through a temporary animated prompt."""
    return animated_input(
        "Enter the URL",
        delay=TYPE_SPEED_NORMAL,
        clear_after=False,
    )


# ============================================================
# TEMPORARY API LOADING DISPLAY
# ============================================================

def show_api_loading(api_status: dict[str, bool]) -> None:
    """
    Display a temporary API loading sequence.

    Example:

        show_api_loading({
            "VirusTotal": bool(vt_key),
            "URLScan.io": bool(urlscan_key),
            "AbuseIPDB": bool(abuse_key),
            "Google Safe Browsing": bool(gsb_key),
        })

    The entire display disappears when completed.
    """
    table = Table(
        show_header=False,
        box=None,
        padding=(0, 1),
    )

    table.add_column("API", min_width=28)
    table.add_column("Status", min_width=18)

    completed_rows: list[tuple[str, str]] = []

    with Live(
        table,
        console=console,
        refresh_per_second=12,
        transient=True,
    ) as live:

        for provider, configured in api_status.items():
            table = Table(
                show_header=False,
                box=None,
                padding=(0, 1),
            )

            table.add_column("API", min_width=28)
            table.add_column("Status", min_width=18)

            for name, status in completed_rows:
                table.add_row(name, status)

            table.add_row(
                provider,
                "[yellow]⠋ Loading...[/yellow]",
            )

            live.update(table)
            time.sleep(1.0)

            if configured:
                final_status = "[green]✓ Loaded[/green]"
            else:
                final_status = "[yellow]○ Skipped[/yellow]"

            completed_rows.append((provider, final_status))

            table = Table(
                show_header=False,
                box=None,
                padding=(0, 1),
            )

            table.add_column("API", min_width=28)
            table.add_column("Status", min_width=18)

            for name, status in completed_rows:
                table.add_row(name, status)

            live.update(table)
            time.sleep(0.3)

        time.sleep(0.55)


# ============================================================
# FUNCTION EXECUTION WITH SPINNER
# ============================================================

def run_with_spinner(
    message: str,
    function: Callable[..., Any],
    *args: Any,
    success_message: Optional[str] = None,
    spinner: str = "dots",
    **kwargs: Any,
) -> Any:
    """
    Run a real function while showing a temporary spinner.

    The spinner disappears after the function completes.

    Example:

        vt_result = run_with_spinner(
            "Running VirusTotal analysis...",
            virustotal_lookup,
            user_url,
            vt_key,
        )
    """
    try:
        with console.status(
            f"[cyan]{message}[/cyan]",
            spinner=spinner,
            spinner_style="bold cyan",
        ):
            result = function(*args, **kwargs)

        if success_message:
            console.print(
                f"[green]✓[/green] {success_message}"
            )
            time.sleep(0.35)
            clear_previous_lines(1)

        return result

    except Exception as error:
        show_error(f"{message} failed: {error}")
        return {
            "status": "Error",
            "message": str(error),
        }


def run_analysis_sequence(
    tasks: list[dict[str, Any]],
) -> dict[str, Any]:
    """
    Run multiple analysis functions sequentially.

    Each task must contain:

        {
            "key": "virustotal",
            "message": "Running VirusTotal analysis...",
            "function": virustotal_lookup,
            "args": (user_url, vt_key),
        }

    Returns a dictionary of results.
    """
    results: dict[str, Any] = {}

    for task in tasks:
        key = task["key"]
        message = task["message"]
        function = task["function"]
        args = task.get("args", ())
        kwargs = task.get("kwargs", {})

        results[key] = run_with_spinner(
            message,
            function,
            *args,
            **kwargs,
        )

    return results


# ============================================================
# PERMANENT GENERAL OUTPUT
# ============================================================

def show_target_url(url: str) -> None:
    """Display the target URL permanently."""
    console.print(
        Panel(
            f"[bold white]{url}[/bold white]",
            title="[bold white]TARGET URL[/bold white]",
            border_style="grey37",
            padding=(1, 2),
        )
    )


def show_section(title: str) -> None:
    """Display a permanent section title."""
    console.print()
    console.rule(
        f"[bold white]{title}[/bold white]",
        style="dim"
    )


def show_success(message: str, permanent: bool = True) -> None:
    """Display a success message."""
    console.print(
        f"[green]✓[/green] {message}"
    )

    if not permanent:
        time.sleep(0.6)
        clear_previous_lines(1)


def show_warning(message: str, permanent: bool = True) -> None:
    """Display a warning message."""
    console.print(
        f"[yellow]⚠[/yellow] {message}"
    )

    if not permanent:
        time.sleep(0.6)
        clear_previous_lines(1)


def show_error(message: str, permanent: bool = True) -> None:
    """Display an error message."""
    console.print(
        f"[red]✗[/red] {message}"
    )

    if not permanent:
        time.sleep(0.8)
        clear_previous_lines(1)


def show_info(message: str, permanent: bool = True) -> None:
    """Display an informational message."""
    console.print(
        f"[cyan]•[/cyan] {message}"
    )

    if not permanent:
        time.sleep(0.6)
        clear_previous_lines(1)


# ============================================================
# STATIC ANALYSIS OUTPUT
# ============================================================

def show_parsed_url(parsed_data: dict[str, Any]) -> None:
    """Display parsed URL information permanently."""
    table = Table(
        title="Parsed URL Information",
        border_style="white",
        show_header=False,
    )

    table.add_column("Field", style="cyan")
    table.add_column("Value", style="white")

    fields = [
        ("Scheme", parsed_data.get("scheme")),
        ("Domain", parsed_data.get("domain")),
        ("Hostname", parsed_data.get("hostname")),
        ("Subdomain", parsed_data.get("subdomain")),
        ("Port", parsed_data.get("port")),
        ("Path", parsed_data.get("path")),
        ("Query", parsed_data.get("query")),
    ]

    for label, value in fields:
        table.add_row(label, str(value))

    console.print(table)


def show_signal(
    suspicious: bool,
    suspicious_message: str,
    normal_message: str,
) -> None:
    """Display one permanent static-analysis signal."""
    if suspicious:
        show_warning(suspicious_message)
    else:
        show_success(normal_message)


# ============================================================
# PERMANENT RISK ENGINE OUTPUT
# ============================================================

def _get_verdict_style(score: int) -> str:
    """Return a Rich style based on the risk score."""
    if score >= 80:
        return "bright_red"

    if score >= 60:
        return " bright_red"

    if score >= 35:
        return "yellow"

    if score >= 15:
        return "cyan"

    return "green"


def show_risk_summary(
    risk_result: dict[str, Any],
    show_breakdown: bool = True,
    show_evidence: bool = True,
    evidence_limit: int = 6,
) -> None:
    """
    Display the permanent final Risk Engine output.

    The information appears one line at a time using
    a fast typewriter effect.
    """
    score = int(risk_result.get("risk_score", 0) or 0)
    verdict = risk_result.get("verdict", "Unknown")
    confidence = int(risk_result.get("confidence", 0) or 0)
    recommendation = risk_result.get(
        "recommendation",
        "No recommendation available.",
    )

    verdict_style = _get_verdict_style(score)

    console.print()

    type_text(
        "CORRELATION COMPLETE",
        delay=TYPE_SPEED_NORMAL,
        style="bold cyan",
    )

    console.print(
        Panel(
            Text.assemble(
                ("Risk Score      : ", "bold white"),
                (f"{score}/100\n", verdict_style),
                ("Verdict         : ", "bold white"),
                (f"{verdict}\n", verdict_style),
                ("Confidence      : ", "bold white"),
                (f"{confidence}%\n", "bold cyan"),
                ("Recommendation  : ", "bold white"),
                (str(recommendation), "bold green"),
            ),
            title="[bold white]FINAL RISK ASSESSMENT[/bold white]",
            border_style=verdict_style.replace("bold ", ""),
            padding=(1, 2),
        )
    )

    if show_breakdown:
        score_breakdown = risk_result.get("score_breakdown", {})

        if score_breakdown:
            type_text(
                "Score Breakdown",
                delay=TYPE_SPEED_NORMAL,
                style="bold cyan",
            )

            table = Table(
                show_header=True,
                header_style="bold cyan",
                border_style="dim"
            )

            table.add_column("Provider")
            table.add_column("Points", justify="right")

            for provider, points in score_breakdown.items():
                display_name = str(provider).replace("_", " ").title()

                table.add_row(
                    display_name,
                    f"+{points}",
                )

            console.print(table)

    if show_evidence:
        evidence = risk_result.get("evidence", [])

        if evidence:
            type_text(
                "Key Risk Evidence",
                delay=TYPE_SPEED_NORMAL,
                style="bold cyan",
            )

            for item in evidence[:evidence_limit]:
                type_text(
                    f"• {item}",
                    delay=TYPE_SPEED_FAST,
                    style="white",
                )


# ============================================================
# PERMANENT REPORT OUTPUT
# ============================================================

def show_report_locations(
    final_report_path: str = (
        "reports/final_report/incident_report.txt"
    ),
    raw_reports_path: str = "reports/raw_rprt/",
    clean_reports_path: str = "reports/clean_rprt/",
) -> None:
    """Display permanent report locations."""

    console.print()

    type_text(
        "Investigation reports generated successfully.",
        delay=TYPE_SPEED_NORMAL,
        style="green",
    )

    report_content = Text()

    report_content.append(
        "Final Incident Report\n",
        style="bold cyan",
    )
    report_content.append(
        f"{final_report_path}\n\n",
        style="bold white",
    )

    report_content.append(
        "Individual Raw Evidence\n",
        style="bold cyan",
    )
    report_content.append(
        f"{raw_reports_path}\n\n",
        style="white",
    )

    report_content.append(
        "Individual Clean Reports\n",
        style="bold cyan",
    )
    report_content.append(
        clean_reports_path,
        style="white",
    )

    console.print(
        Panel(
            report_content,
            title="[bold white]REPORT LOCATIONS[/bold white]",
            border_style="grey37",
            padding=(1, 2),
        )
    )


def show_completion_message() -> None:
    """Display the final permanent completion message."""
    console.print()
    console.rule(style="dim")

    type_text(
        "INVESTIGATION COMPLETED SUCCESSFULLY",
        delay=TYPE_SPEED_SLOW,
        style="bold white ",
    )

    console.rule(style="dim")


    

