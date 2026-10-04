"""
GroundedCVE Triage & AI Priority Scoring CLI Runner.
Executes the Scope Pre-Filter, AI Practical Severity Assessment,
100-Point Priority Scoring, and CVSS Discrepancy Anomaly Check.
"""
import argparse
import json
import logging
from pathlib import Path
import sys

# Add project root to sys.path so Backend modules import cleanly
ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from Backend.config import STAGING_DIR
from Backend.ingestion.collectors.cisa_kev import CisaKevCollector
from Backend.ingestion.models import StagingEnvelope
from Backend.triage.models import ScopeCategory
from Backend.triage.priority_scorer import PriorityScoringEngine

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich import print as rprint
    HAVE_RICH = True
except ImportError:
    HAVE_RICH = False


def setup_logging(verbose: bool):
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )


def load_envelopes(staging_file: Path) -> list[StagingEnvelope]:
    if not staging_file.exists():
        print(f"Error: Staging file not found at {staging_file}.")
        print("Run `python Backend/run_ingestion.py` first to collect live data.")
        sys.exit(1)

    with open(staging_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    return [StagingEnvelope.model_validate(item) for item in data]


def print_rich_triage_dashboard(candidates, console: "Console", output_file: Path):
    console.print("\n[bold cyan]========================================================================[/bold cyan]")
    console.print("[bold yellow]       GroundedCVE - Pentest Scope Pre-Filter & AI Scoring Engine       [/bold yellow]")
    console.print("[bold cyan]========================================================================[/bold cyan]\n")

    # Table of candidates
    table = Table(
        title="[bold green]Candidate Triage & Priority Scoring Leaderboard (100-Point Scale)[/bold green]",
        show_header=True,
        header_style="bold magenta",
    )
    table.add_column("Rank", justify="center", style="dim", width=6)
    table.add_column("Scope", justify="center", width=12)
    table.add_column("Title / CVE", style="cyan", width=38)
    table.add_column("AI Severity", justify="center", width=12)
    table.add_column("CVSS", justify="center", width=8)
    table.add_column("Score (100)", justify="right", style="bold green", width=12)
    table.add_column("Anomaly Check", justify="center", width=16)

    in_scope_count = 0
    discrepancies = []

    for idx, c in enumerate(candidates, start=1):
        cat = c.pre_filter.category
        if cat == ScopeCategory.WEB:
            cat_styled = "[bold cyan][WEB][/bold cyan]"
            in_scope_count += 1
        elif cat == ScopeCategory.MOBILE:
            cat_styled = "[bold green][MOBILE][/bold green]"
            in_scope_count += 1
        else:
            cat_styled = "[dim][OUT OF SCOPE][/dim]"

        title_display = f"{c.envelope.CVE_ID}: {c.envelope.Title[:30]}..." if c.envelope.CVE_ID else c.envelope.Title[:34]

        ai_display = f"{c.ai_assessment.severity_score}/10" if c.ai_assessment else "[dim]-[/dim]"
        cvss_display = str(c.envelope.CVSS) if c.envelope.CVSS is not None else "[dim]N/A[/dim]"

        if c.discrepancy and c.discrepancy.is_discrepancy:
            anomaly_display = "[bold red][!] DISCREPANCY[/bold red]"
            discrepancies.append(c)
        elif not c.pre_filter.is_in_scope:
            anomaly_display = "[dim]BYPASS[/dim]"
        else:
            anomaly_display = "[green]ALIGNED[/green]"

        score_display = f"{c.priority_score:.1f}" if c.pre_filter.is_in_scope else "[dim]0.0[/dim]"

        table.add_row(
            str(idx),
            cat_styled,
            title_display,
            ai_display,
            cvss_display,
            score_display,
            anomaly_display,
        )

    console.print(table)

    console.print(f"\n[bold]Total Ingested:[/bold] {len(candidates)}")
    console.print(f"[bold]In-Scope Pentesting Items:[/bold] [green]{in_scope_count}[/green]")
    console.print(f"[bold]Out-of-Scope Items Filtered:[/bold] [dim]{len(candidates) - in_scope_count}[/dim]")
    console.print(f"[bold]Saved Triaged Dataset:[/bold] [underline cyan]{output_file}[/underline cyan]")

    # Print Discrepancy Warnings Panel if any triggered
    if discrepancies:
        console.print("\n[bold red]--- CVSS vs AI Severity Discrepancy Diagnostics ---[/bold red]")
        for d in discrepancies:
            disc = d.discrepancy
            diag_text = (
                f"[bold cyan]{d.envelope.Title}[/bold cyan]\n"
                f"- [bold]Official CVSS:[/bold] {disc.cvss_score}  |  [bold]AI Severity Score:[/bold] {disc.ai_severity}/10.0  |  [bold]Delta (|d|):[/bold] [bold red]{disc.delta}[/bold red]\n"
                f"- [bold yellow]Troubleshooting Diagnosis:[/bold yellow] {disc.troubleshoot_note}"
            )
            console.print(Panel(diag_text, title=f"[bold red]Anomaly Alert: {d.envelope.CVE_ID or d.envelope.Item_ID}[/bold red]", border_style="red"))


def main():
    parser = argparse.ArgumentParser(
        description="GroundedCVE Scope Pre-Filtering & AI Priority Scoring Engine",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--input",
        type=Path,
        default=STAGING_DIR / "latest_envelopes.json",
        help="Path to staging envelopes JSON file",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=STAGING_DIR / "triaged_candidates.json",
        help="Path to save scored and triaged candidates",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose debug logging",
    )

    args = parser.parse_args()
    setup_logging(args.verbose)

    print(f"Loading staging envelopes from {args.input}...")
    envelopes = load_envelopes(args.input)

    # Fetch live CISA KEV catalog for active exploitation ground truth
    print("Loading active weaponization signals from CISA KEV catalog...")
    try:
        kev_collector = CisaKevCollector()
        kev_items = kev_collector.collect(limit=500)
        kev_set = {item.CVE_ID.upper() for item in kev_items if item.CVE_ID}
    except Exception as e:
        print(f"Warning: Could not fetch CISA KEV live ({e}). Utilizing fallback cache.")
        kev_set = {"CVE-2026-88772", "CVE-2026-88771", "CVE-2024-0044"}

    engine = PriorityScoringEngine(kev_catalog=kev_set)

    print(f"Executing Pre-Filter Gate & AI Severity Scoring across {len(envelopes)} items...")
    candidates = engine.triage_batch(envelopes)

    # Save to JSON
    with open(args.output, "w", encoding="utf-8") as f:
        json_data = [c.model_dump() for c in candidates]
        json.dump(json_data, f, indent=2, ensure_ascii=False)

    if HAVE_RICH:
        console = Console()
        print_rich_triage_dashboard(candidates, console, args.output)
    else:
        print("\nTriage execution completed successfully.")
        print(f"Saved {len(candidates)} triaged candidates to {args.output}")


if __name__ == "__main__":
    main()
