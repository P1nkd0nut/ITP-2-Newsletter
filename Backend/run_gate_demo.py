"""
Verification Gate Fault-Injection Demo (Task 3.2 test plan).

For each of the 20 ground-truth items:
  1. Build a CLEAN draft card that only uses facts from the source -> should PASS.
  2. Build 7 SABOTAGED copies, each with one planted fake fact  -> should be QUARANTINED.
Then report what the gate caught.

Usage:
    python Backend/run_gate_demo.py
"""
import re
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from rich.console import Console
from rich.table import Table

from Backend.run_benchmark import load_ground_truth_dataset, convert_gt_to_envelope
from Backend.verification.gate import IMPACT_TERMS, VERSION_RE, VerificationGate
from Backend.verification.models import DraftCard

console = Console()


def make_clean_card(item) -> DraftCard:
    """A faithful draft: every fact is copied from the item's source."""
    sentences = re.split(r"(?<=\.)\s+", item["raw_content"], maxsplit=1)
    return DraftCard(
        mechanism=f"{item['cve_id']} (CVSS {item['cvss']}, {item['cwe'][0]}): {sentences[0]}",
        impact=sentences[1] if len(sentences) > 1 else "",
        testing_syntax=list(item["poc_commands"]),
        remediation="Apply the vendor patch referenced in the advisory.",
        references=[item["official_url"]],
    )


def make_faults(item, clean: DraftCard) -> dict:
    """Seven copies of the clean card, each with exactly one planted fake fact."""
    faults = {}

    # 1. Fake CVE: change the last digit of the real ID (a typical AI slip)
    cve = item["cve_id"]
    fake_cve = cve[:-1] + str((int(cve[-1]) + 1) % 10)
    faults["Fake CVE ID"] = clean.model_copy(update={"mechanism": clean.mechanism.replace(cve, fake_cve)})

    # 2. Altered version: a version string that is NOT in the source
    versions = VERSION_RE.findall(item["raw_content"])
    fake_v = versions[0] if versions else "99.4"
    while fake_v in item["raw_content"]:
        fake_v = fake_v + ".1"
    faults["Altered version"] = clean.model_copy(update={"impact": clean.impact + f" Fixed in version {fake_v}."})

    # 3. Invented flag on the PoC command
    cmds = list(clean.testing_syntax) or ["curl -k https://target.local"]
    cmds[0] = cmds[0] + " --disable-auth-check"
    faults["Invented flag"] = clean.model_copy(update={"testing_syntax": cmds})

    # 4. Fabricated reference link
    faults["Fake URL"] = clean.model_copy(
        update={"references": clean.references + [f"https://github.com/fake-researcher/{cve.lower()}-exploit"]}
    )

    # 5. Impact the source never mentions
    raw = item["raw_content"].lower()
    absent = next(
        name for name, phrases in IMPACT_TERMS.items()
        if not any(re.search(rf"\b{re.escape(p)}\b", raw) for p in phrases)
    )
    faults["Made-up impact"] = clean.model_copy(update={"impact": clean.impact + f" This leads to {absent}."})

    # 6. Wrong CVSS score
    wrong_cvss = round(item["cvss"] - 3.0, 1) if item["cvss"] >= 5 else round(item["cvss"] + 4.0, 1)
    faults["Wrong CVSS"] = clean.model_copy(
        update={"mechanism": clean.mechanism.replace(f"CVSS {item['cvss']}", f"CVSS {wrong_cvss}")}
    )

    # 7. Wrong CWE
    fake_cwe = "CWE-79" if "CWE-79" not in item["cwe"] else "CWE-89"
    faults["Wrong CWE"] = clean.model_copy(
        update={"mechanism": clean.mechanism.replace(item["cwe"][0], fake_cwe)}
    )
    return faults


def main():
    gate = VerificationGate()
    items = load_ground_truth_dataset()

    clean_passed = 0
    caught = {}  # fault name -> [caught, total]
    example = None

    for item in items:
        env = convert_gt_to_envelope(item)
        evidence = item["poc_commands"]  # stands in for Tier 2 PoC chunks until Task 2.2 exists

        clean = make_clean_card(item)
        result = gate.verify(clean, env, evidence)
        if result.passed:
            clean_passed += 1
        else:
            console.print(f"[yellow]False quarantine on {item['id']}: {result.failures}[/yellow]")

        for name, bad_card in make_faults(item, clean).items():
            r = gate.verify(bad_card, env, evidence)
            stats = caught.setdefault(name, [0, 0])
            stats[1] += 1
            if not r.passed:
                stats[0] += 1
            if example is None and name == "Invented flag":
                example = (item["id"], r)

    # ---- Results table
    table = Table(title="[bold]Verification Gate - Fault Injection Results (20 ground-truth items)[/bold]")
    table.add_column("Planted fault", style="cyan")
    table.add_column("Caught", justify="right")
    table.add_column("Detection rate", justify="right", style="bold green")
    total_caught = total_faults = 0
    for name, (c, t) in caught.items():
        table.add_row(name, f"{c}/{t}", f"{c / t * 100:.0f}%")
        total_caught += c
        total_faults += t
    table.add_row("[bold]ALL FAULTS[/bold]", f"{total_caught}/{total_faults}", f"{total_caught / total_faults * 100:.1f}%")
    console.print(table)

    console.print(f"\nClean drafts passed: [bold green]{clean_passed}/{len(items)}[/bold green] "
                  f"(false-quarantine rate {(len(items) - clean_passed) / len(items) * 100:.1f}%)")

    # ---- One example of what a quarantine looks like
    item_id, r = example
    console.print(f"\n[bold red]Example quarantine ({item_id}, invented flag):[/bold red]")
    for f in r.failures:
        console.print(f"  [{f.check}] {f.value[:80]}\n      -> {f.reason}")

    # ---- Retry-then-quarantine demo
    item = items[0]
    env = convert_gt_to_envelope(item)
    clean = make_clean_card(item)
    bad = make_faults(item, clean)["Fake CVE ID"]

    _, r1 = gate.verify_with_retry(lambda fb: bad if fb is None else clean, env, item["poc_commands"])
    _, r2 = gate.verify_with_retry(lambda fb: bad, env, item["poc_commands"])
    console.print("\n[bold]Retry logic:[/bold]")
    console.print(f"  AI fixes its mistake on retry  -> {r1.status} after {r1.attempts} attempts")
    console.print(f"  AI repeats the mistake         -> {r2.status} after {r2.attempts} attempts")


if __name__ == "__main__":
    main()
