"""
GroundedCVE Threat Intelligence Ingestion CLI Runner.
Interactive execution script designed for demonstration, testing, and automated runs.
"""
import argparse
import json
import logging
import sys
from pathlib import Path

# Add project root to sys.path so Backend modules import cleanly
ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from Backend.ingestion.pipeline import IngestionPipeline

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


def print_rich_summary(summary: dict, console: "Console"):
    console.print("\n[bold cyan]===========================================================[/bold cyan]")
    console.print("[bold yellow]       GroundedCVE - Threat Intelligence Ingestion Stage   [/bold yellow]")
    console.print("[bold cyan]===========================================================[/bold cyan]\n")

    # Table of sources
    table = Table(title="[bold green]Ingestion Feed Execution Summary[/bold green]", show_header=True, header_style="bold magenta")
    table.add_column("Feed / Source", style="cyan", width=32)
    table.add_column("Items Fetched", justify="right", style="green", width=16)
    table.add_column("Status", justify="center", width=12)

    source_counts = summary.get("source_counts", {})
    errors = summary.get("errors", {})

    for src, count in source_counts.items():
        if count > 0:
            status = "[bold green]OK[/bold green]"
        elif src in errors:
            status = "[bold red]ERROR[/bold red]"
        else:
            status = "[dim]0 items[/dim]"
        table.add_row(src, str(count), status)

    console.print(table)

    console.print(f"\n[bold]Total Items Captured:[/bold] {summary['total_collected']}")
    console.print(f"[bold]Unique Staging Envelopes:[/bold] {summary['unique_envelopes']}")
    console.print(f"[bold]Execution Duration:[/bold] {summary['duration_seconds']}s")
    if summary.get("output_file"):
        console.print(f"[bold]Staging JSON File:[/bold] [underline cyan]{summary['output_file']}[/underline cyan]")

    # Preview 2 sample envelopes
    envelopes = summary.get("envelopes", [])
    if envelopes:
        console.print("\n[bold yellow]--- Sample Staging Envelopes Preview ---[/bold yellow]")
        for env in envelopes[:2]:
            meta = []
            if env.CVE_ID:
                meta.append(f"[bold]CVE:[/bold] {env.CVE_ID}")
            if env.CVSS:
                meta.append(f"[bold]CVSS:[/bold] {env.CVSS} ({env.CVSS_Version})")
            if env.CWE:
                meta.append(f"[bold]CWE:[/bold] {env.CWE}")
            if env.KEV_Status:
                meta.append("[bold red]CISA KEV: YES[/bold red]")
            if env.Vendor_Product:
                meta.append(f"[bold]Target:[/bold] {env.Vendor_Product}")

            preview_text = (
                f"[bold cyan]{env.Title}[/bold cyan]\n"
                f"[dim]ID:[/dim] {env.Item_ID}  |  [dim]Type:[/dim] {env.Source_Type.value}  |  [dim]Published:[/dim] {env.Published_Date}\n"
                f"[dim]Source URL:[/dim] {env.Source_URL}\n"
                f"[dim]Content-Hash (SHA-256):[/dim] {env.Content_Hash[:24]}...\n"
                + ("  |  ".join(meta) + "\n" if meta else "")
                + f"\n[italic dim]Raw Content Preview (first 200 chars):[/italic dim]\n"
                f"{env.Raw_Content[:200].strip()}..."
            )
            console.print(Panel(preview_text, title=f"[bold]{env.Source_Type.value} Envelope[/bold]", expand=False))


def print_plain_summary(summary: dict):
    print("=" * 60)
    print("       GroundedCVE - Threat Intelligence Ingestion Stage")
    print("=" * 60)
    for src, count in summary.get("source_counts", {}).items():
        print(f" - {src:<32}: {count:>4} items")
    print(f"\nTotal Captured: {summary['total_collected']}")
    print(f"Unique Envelopes: {summary['unique_envelopes']}")
    print(f"Duration: {summary['duration_seconds']}s")
    if summary.get("output_file"):
        print(f"Saved to: {summary['output_file']}")


def main():
    parser = argparse.ArgumentParser(
        description="GroundedCVE Phase 1 Data Ingestion Runner",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=3,
        help="Max items to fetch per collector (keep small for quick demos)",
    )
    parser.add_argument(
        "--sources",
        type=str,
        default=None,
        help="Comma-separated list of sources to run (e.g. 'cisa_kev,portswigger,nvd'). Defaults to all.",
    )
    parser.add_argument(
        "--poc",
        action="store_true",
        help="Enable public GitHub PoC detection enrichment for CVEs",
    )
    parser.add_argument(
        "--list-sources",
        action="store_true",
        help="List all registered threat feed collectors and exit",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose debug logging",
    )

    args = parser.parse_args()
    setup_logging(args.verbose)

    pipeline = IngestionPipeline(enable_poc_detection=args.poc)

    if args.list_sources:
        print("Available sources:")
        for s in pipeline.list_available_sources():
            print(f"  - {s}")
        return

    source_list = [s.strip() for s in args.sources.split(",")] if args.sources else None

    print(f"Starting GroundedCVE data ingestion (limit={args.limit} per source)...")
    summary = pipeline.run(sources=source_list, limit_per_source=args.limit)

    if HAVE_RICH:
        console = Console()
        print_rich_summary(summary, console)
    else:
        print_plain_summary(summary)


if __name__ == "__main__":
    main()
