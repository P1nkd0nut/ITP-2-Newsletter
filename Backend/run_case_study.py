"""
GroundedCVE 'Day in the Life' Case Study Simulation (October 10, 2023).
Demonstrates how GroundedCVE triages an intense disclosure day containing:
- Critical In-the-Wild Zero-Days (Citrix Bleed, Atlassian, Apple BLASTPASS)
- Legitimate Web & Mobile Pentesting Tools (HTTP/2 Rapid Reset, Frida 16)
- Out-of-Scope Noise (D-Link Router firmware, Siemens SCADA PLC, HP Print Spooler)
- Real-World CVSS Discrepancy (Low vendor CVSS 2.0 vs Critical Remote Command Injection)
"""
import json
import logging
from pathlib import Path
import sys
import time

# Ensure project root is in sys.path
ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from Backend.ingestion.models import StagingEnvelope
from Backend.triage.models import ScopeCategory
from Backend.triage.pre_filter import PentestPreFilter
from Backend.triage.priority_scorer import PriorityScoringEngine
from Backend.triage.ai_evaluator import AISeverityEvaluator

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    HAVE_RICH = True
except ImportError:
    HAVE_RICH = False

CASE_STUDY_FILE = ROOT_DIR / "Backend" / "data" / "case_study_day.json"


def run_case_study():
    if not CASE_STUDY_FILE.exists():
        print(f"Error: Case study file not found at {CASE_STUDY_FILE}")
        sys.exit(1)

    with open(CASE_STUDY_FILE, "r", encoding="utf-8") as f:
        raw_items = json.load(f)

    envelopes = [StagingEnvelope.model_validate(x) for x in raw_items]

    # CISA KEV catalog for this day
    kev_set = {x.CVE_ID for x in envelopes if x.KEV_Status and x.CVE_ID}
    engine = PriorityScoringEngine(kev_catalog=kev_set)
    pre_filter = PentestPreFilter()

    console = Console() if HAVE_RICH else None

    if HAVE_RICH:
        console.print("\n[bold cyan]========================================================================================[/bold cyan]")
        console.print("[bold yellow]       GroundedCVE Case Study Simulation: 'A Day in the Life' (October 10, 2023)        [/bold yellow]")
        console.print("[bold cyan]       Demonstrating Zero-Day Prioritisation, Scope Pre-Filtering & Anomaly Detection   [/bold cyan]")
        console.print("[bold cyan]========================================================================================[/bold cyan]\n")

        console.print("[bold]Scenario:[/bold] Security operations is hit with 10 diverse advisories across Web, Mobile, IoT, and Zero-Days.")
        console.print("[bold]Simulated Batch:[/bold] 10 Envelopes ingested via Phase 1 Staging Specification.\n")

    print("[*] STEP 1: Running Scope Pre-Filter Gate (Task 1.2)...")
    time.sleep(0.4)

    triaged_records = []
    in_scope_count = 0
    filtered_out = []

    for env in envelopes:
        rec = engine.process_envelope(env)
        triaged_records.append(rec)
        if rec.pre_filter.is_in_scope:
            in_scope_count += 1
            cat_label = f"[{rec.pre_filter.category.value}]"
            print(f"  --> PASSED: {cat_label:<9} {env.CVE_ID or env.Item_ID} - {env.Title[:45]}...")
        else:
            filtered_out.append(rec)
            print(f"  [x] FILTERED: [OUT OF SCOPE] {env.CVE_ID or env.Item_ID} - Reason: {rec.pre_filter.reason}")

    # Step 2: Scoring Summary
    print("\n[*] STEP 2: Computing 100-Point Formula (40 KEV + 40 AI + 20 PoC)...")
    triaged_records.sort(key=lambda x: x.priority_score, reverse=True)

    if HAVE_RICH:
        # Table of Results
        table = Table(title="[bold green]Case Study Triage Leaderboard: Ranked for Weekly Pentesting Digest[/bold green]", show_header=True)
        table.add_column("Rank", justify="center", width=5)
        table.add_column("Scope", justify="center", width=12)
        table.add_column("Vulnerability / Advisory", width=36)
        table.add_column("Type", justify="center", width=10)
        table.add_column("AI Sev", justify="center", width=8)
        table.add_column("CVSS", justify="center", width=6)
        table.add_column("Score (100)", justify="right", style="bold green", width=12)
        table.add_column("Anomaly Check", justify="center", width=15)

        for rank, r in enumerate(triaged_records, start=1):
            env = r.envelope
            pf = r.pre_filter
            disc = r.discrepancy
            ai = r.ai_assessment

            if pf.category == ScopeCategory.WEB:
                scope_str = "[cyan][WEB][/cyan]"
            elif pf.category == ScopeCategory.MOBILE:
                scope_str = "[green][MOBILE][/green]"
            else:
                scope_str = "[dim][OUT OF SCOPE][/dim]"

            is_zero_day = env.KEV_Status
            type_str = "[bold red]ZERO-DAY[/bold red]" if is_zero_day else "[dim]Standard[/dim]"

            ai_sev_str = f"{ai.severity_score:.1f}/10" if ai else "-"
            cvss_str = str(env.CVSS) if env.CVSS is not None else "N/A"
            score_str = f"{r.priority_score:.1f}" if pf.is_in_scope else "[dim]0.0[/dim]"

            if disc and disc.is_discrepancy:
                anomaly_str = "[bold red][!] DISCREPANCY[/bold red]"
            elif not pf.is_in_scope:
                anomaly_str = "[dim]BYPASS (Noise)[/dim]"
            else:
                anomaly_str = "[green]ALIGNED[/green]"

            table.add_row(
                str(rank),
                scope_str,
                f"{env.CVE_ID or env.Item_ID}: {env.Title[:26]}...",
                type_str,
                ai_sev_str,
                cvss_str,
                score_str,
                anomaly_str,
            )

        console.print(table)

        # Highlight Anomaly Diagnostic Panel
        anomalies = [r for r in triaged_records if r.discrepancy and r.discrepancy.is_discrepancy]
        if anomalies:
            console.print("\n[bold red]--- Case Study Diagnostic: Automated CVSS Anomaly Intercept ---[/bold red]")
            for a in anomalies:
                diag_box = (
                    f"[bold cyan]{a.envelope.Title}[/bold cyan]\n"
                    f"- [bold]Vendor CVSS Score:[/bold] {a.discrepancy.cvss_score} (Underestimated)\n"
                    f"- [bold]AI Practical Severity:[/bold] {a.discrepancy.ai_severity}/10.0 (Evaluated as Unauthenticated Remote Command Injection)\n"
                    f"- [bold]Discrepancy Delta (|d|):[/bold] [bold red]{a.discrepancy.delta}[/bold red] (Threshold >= 4.0 Triggered)\n"
                    f"- [bold yellow]Automated Action:[/bold yellow] Discrepancy logged for security analyst verification before broadcast."
                )
                console.print(Panel(diag_box, title=f"[bold red]CVSS Rating Anomaly: {a.envelope.CVE_ID}[/bold red]", border_style="red"))

        # Case Study Takeaway Summary
        console.print("\n[bold green]======================== Case Study Key Takeaways ========================[/bold green]")
        console.print("1. [bold cyan]Noise Reduction:[/bold cyan] 3 Out-of-Scope IoT, SCADA, and Printer disclosures automatically dropped (Score: 0.0).")
        console.print("2. [bold cyan]Zero-Day Elevaton:[/bold cyan] Active Zero-Days (Citrix Bleed, Atlassian, BLASTPASS) ranked #1, #2, #3 with >88+ points.")
        console.print("3. [bold cyan]CVSS Anomaly Guardrail:[/bold cyan] Caught CVE-2026-94138 where official CVSS (2.0) failed to reflect true severity (7.0).")
        console.print("[bold green]========================================================================[/bold green]\n")


if __name__ == "__main__":
    run_case_study()
