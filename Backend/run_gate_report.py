"""
Gate effectiveness on REAL generated cards (plan Task 4.1).

run_gate_demo.py measures the gate on planted faults. This script measures it
on the cards the summariser actually wrote:

    # 1. How the gate treated every real draft: passed first time, passed after
    #    one retry, quarantined, or errored; and which checks failed
    python Backend/run_gate_report.py summary

    # 2. Re-run the CURRENT gate over the published cards and their own chunks.
    #    A published card that now fails is a false quarantine (the card was fine
    #    but a newer check rejects it) or a real error the older gate missed;
    #    the output lists each one for a person to decide.
    python Backend/run_gate_report.py recheck

    # 3. Manual review: write a worksheet of published cards (CSV, opens in Excel),
    #    fill in the reviewer_* columns with Y / N, then score it. This catches
    #    errors token checks can't, such as a wrongly stated impact.
    python Backend/run_gate_report.py worksheet --size 15
    python Backend/run_gate_report.py score Backend/data/manual_checks/card_review_YYYYMMDD.csv
"""
import argparse
import csv
import json
import random
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from Backend.config import DATA_DIR, GROUNDED_CARDS_FILE, QUARANTINE_LOG_FILE, STAGING_DIR

ENVELOPES_FILE = STAGING_DIR / "latest_envelopes.json"
CHUNKS_FILE = STAGING_DIR / "latest_chunks.json"
OUT_DIR = DATA_DIR / "manual_checks"

# Each reviewer column: Y = the card is right on this point, N = wrong, NA = not applicable
REVIEW_CHECKS = {
    "reviewer_facts_ok": "IDs, versions and scores match the source",
    "reviewer_impact_ok": "Impact is stated as the source states it (not exaggerated or invented)",
    "reviewer_commands_ok": "Testing commands are copied correctly and make sense",
    "reviewer_remediation_ok": "Remediation matches the vendor's advice",
}


def load_json(path: Path, default):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return default


def load_records(cards_file: Path = GROUNDED_CARDS_FILE, log_file: Path = QUARANTINE_LOG_FILE) -> List[Dict[str, Any]]:
    """Published (PASSED) cards plus every quarantined/errored record, latest per item."""
    records: Dict[str, Dict[str, Any]] = {}
    try:
        lines = log_file.read_text(encoding="utf-8").splitlines()
    except OSError:
        lines = []
    for line in lines:
        try:
            r = json.loads(line)
        except ValueError:
            continue
        records[r.get("Item_ID")] = r
    for r in load_json(cards_file, []):
        records[r.get("Item_ID")] = r  # a later PASSED card replaces an older failure
    return list(records.values())


def summarise(records: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
    outcome = Counter()
    failed_checks = Counter()
    for r in records:
        status = r.get("status")
        attempts = (r.get("verification") or {}).get("attempts", 1)
        if status == "PASSED":
            outcome["passed_first_try" if attempts == 1 else "passed_after_retry"] += 1
        elif status == "QUARANTINED":
            outcome["quarantined"] += 1
        else:
            outcome["error"] += 1
        for f in (r.get("verification") or {}).get("failures") or []:
            failed_checks[f.get("check")] += 1
    drafted = outcome["passed_first_try"] + outcome["passed_after_retry"] + outcome["quarantined"]
    return {
        "cards_drafted": drafted,
        **{k: outcome[k] for k in ("passed_first_try", "passed_after_retry", "quarantined", "error")},
        "first_try_pass_rate": outcome["passed_first_try"] / drafted if drafted else 0.0,
        "quarantine_rate": outcome["quarantined"] / drafted if drafted else 0.0,
        "failures_by_check": dict(failed_checks),
    }


def recheck(records: Iterable[Dict[str, Any]], envelopes: Dict[str, Any], chunks: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Run today's gate over each published card with the chunks it was written from."""
    from Backend.ingestion.models import StagingEnvelope
    from Backend.verification.gate import VerificationGate
    from Backend.verification.models import DraftCard

    gate = VerificationGate()
    text_by_chunk = {c.get("Chunk_ID"): c.get("Text", "") for c in chunks}
    checked, now_failing, skipped = 0, [], 0
    for r in records:
        if r.get("status") != "PASSED" or not r.get("card"):
            continue
        env = envelopes.get(r.get("Item_ID"))
        if env is None:
            skipped += 1
            continue
        evidence = [text_by_chunk[i] for i in r.get("chunk_ids") or [] if i in text_by_chunk]
        result = gate.verify(DraftCard(**r["card"]), StagingEnvelope(**env), evidence=evidence)
        checked += 1
        if not result.passed:
            now_failing.append({"Item_ID": r["Item_ID"], "failures": [f.model_dump() for f in result.failures]})
    return {
        "published_cards_rechecked": checked,
        "skipped_no_envelope": skipped,
        "now_failing": now_failing,
        "now_failing_rate": len(now_failing) / checked if checked else 0.0,
    }


def write_worksheet(records: List[Dict[str, Any]], size: int, out_dir: Path = OUT_DIR, seed: int = 0) -> Path:
    published = [r for r in records if r.get("status") == "PASSED" and r.get("card")]
    sample = random.Random(seed).sample(published, min(size, len(published)))
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"card_review_{datetime.now(timezone.utc):%Y%m%d}.csv"
    with open(path, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f)
        w.writerow(["Item_ID", "CVE_ID", "Source_URL", "mechanism", "impact", "testing_syntax", "remediation",
                    *REVIEW_CHECKS, "reviewer_name", "notes"])
        for r in sample:
            c = r["card"]
            w.writerow([r.get("Item_ID"), r.get("CVE_ID") or "", r.get("Source_URL"), c.get("mechanism"),
                        c.get("impact"), " | ".join(c.get("testing_syntax") or []), c.get("remediation"),
                        *([""] * len(REVIEW_CHECKS)), "", ""])
    return path


def score_worksheet(path: Path) -> Dict[str, Any]:
    with open(path, newline="", encoding="utf-8-sig") as f:
        rows = list(csv.DictReader(f))
    per_check = {}
    cards_with_error = 0
    for row in rows:
        if any((row.get(col) or "").strip().upper() == "N" for col in REVIEW_CHECKS):
            cards_with_error += 1
    for col in REVIEW_CHECKS:
        marks = [(row.get(col) or "").strip().upper() for row in rows]
        judged = [m for m in marks if m in ("Y", "N")]
        per_check[col] = {"judged": len(judged), "wrong": judged.count("N")}
    reviewed = sum(1 for row in rows if any((row.get(c) or "").strip() for c in REVIEW_CHECKS))
    return {
        "cards_reviewed": reviewed,
        "cards_with_an_error": cards_with_error,
        "manual_error_rate": cards_with_error / reviewed if reviewed else 0.0,
        "per_check": per_check,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="cmd")
    sub.add_parser("summary")
    sub.add_parser("recheck")
    ws = sub.add_parser("worksheet")
    ws.add_argument("--size", type=int, default=15)
    sc = sub.add_parser("score")
    sc.add_argument("csv", type=Path)
    args = parser.parse_args()

    records = load_records()
    if args.cmd in (None, "summary"):
        print(json.dumps(summarise(records), indent=2))
    elif args.cmd == "recheck":
        envelopes = {e["Item_ID"]: e for e in load_json(ENVELOPES_FILE, [])}
        result = recheck(records, envelopes, load_json(CHUNKS_FILE, []))
        print(json.dumps(result, indent=2))
    elif args.cmd == "worksheet":
        path = write_worksheet(records, args.size)
        print(f"Wrote {path}. Fill in the reviewer_* columns with Y / N / NA, then run:\n"
              f"  python Backend/run_gate_report.py score {path.relative_to(ROOT_DIR)}")
    elif args.cmd == "score":
        print(json.dumps(score_worksheet(args.csv), indent=2))


if __name__ == "__main__":
    main()
