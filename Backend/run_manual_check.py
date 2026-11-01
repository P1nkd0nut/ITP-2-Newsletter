"""
GroundedCVE manual spot-check helper.

The automated checks (scope filter, AI severity, PoC search, link health,
change tracking, age-based re-checks) all need a human to confirm they are
right. This script picks a small, varied sample of triaged items and writes a
worksheet the team fills in by hand, then scores the filled worksheet.

    # 1. Pick a sample and write a worksheet (CSV opens in Excel)
    python Backend/run_manual_check.py sample --size 12

    # 2. Fill in the reviewer_* columns with Y / N (or NA), save the CSV

    # 3. Score it: agreement per check, plus every disagreement
    python Backend/run_manual_check.py score Backend/data/manual_checks/manual_check_YYYYMMDD.csv

See Testing/MANUAL_CHECKS.md for what to check in each column.
"""
import argparse
import csv
import json
import random
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from Backend.config import DATA_DIR, STAGING_DIR
from Backend.ingestion.recheck_policy import age_days, is_frozen, recency_label, recheck_interval_days

DEFAULT_INPUT = STAGING_DIR / "triaged_candidates.json"
DEFAULT_OUT_DIR = DATA_DIR / "manual_checks"

# Each reviewer column is one check. Y = the system got it right, N = wrong, NA = not applicable.
CHECKS = {
    "reviewer_scope_ok": "Scope (in/out and WEB/MOBILE category)",
    "reviewer_severity_ok": "AI severity and priority score",
    "reviewer_poc_ok": "PoC links are real PoCs for this CVE",
    "reviewer_links_ok": "Source and reference links open and are relevant",
    "reviewer_change_ok": "New / Updated / Unchanged label",
    "reviewer_schedule_ok": "Re-check tier / freeze matches the CVE's age",
}

COLUMNS = [
    "cve_id", "title", "why_sampled", "recency", "recheck_schedule",
    "source_url", "nvd_url",
    "system_in_scope", "system_category", "system_scope_reason",
    "system_ai_severity", "official_cvss", "system_priority_score", "system_discrepancy",
    "system_poc_urls", "system_change_status", "system_change_summary",
    *CHECKS.keys(), "reviewer_notes",
]

# Strata: every sample tries to include at least one item from each, so the
# reviewer sees the cases most likely to be wrong, not just the easy ones.
STRATA = [
    ("in scope", lambda c: _pf(c).get("is_in_scope") is True),
    ("out of scope", lambda c: _pf(c).get("is_in_scope") is False),
    ("has PoC", lambda c: bool(_env(c).get("PoC_URLs"))),
    ("no PoC", lambda c: not _env(c).get("PoC_URLs")),
    ("CISA KEV", lambda c: bool(_env(c).get("KEV_Status"))),
    ("AI vs CVSS discrepancy", lambda c: bool((c.get("discrepancy") or {}).get("is_discrepancy"))),
    ("marked Updated", lambda c: str(_env(c).get("Change_Status") or "").upper() == "UPDATED"),
    ("under 1 month old", lambda c: _age(c) is not None and _age(c) <= 30),
    ("1-6 months old", lambda c: _age(c) is not None and 30 < _age(c) <= 180),
    ("6-12 months old", lambda c: _age(c) is not None and 180 < _age(c) <= 365),
    ("over 1 year (frozen)", lambda c: is_frozen(_env(c).get("Published_Date"))),
]


def _env(c):
    return c.get("envelope") or {}


def _pf(c):
    return c.get("pre_filter") or {}


def _age(c):
    return age_days(_env(c).get("Published_Date"))


def schedule_text(published):
    interval = recheck_interval_days(published)
    if interval is None:
        return "frozen (not updated)"
    return "every run" if interval <= 1 else f"every {interval} days"


def load_candidates(path):
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    return data.get("items", []) if isinstance(data, dict) else data


def pick_sample(candidates, size, seed=None):
    """One random item per stratum first (if any exist), then random fill up to size."""
    rng = random.Random(seed)
    chosen, reasons = [], {}

    def key(c):
        return _env(c).get("Item_ID") or _env(c).get("CVE_ID") or id(c)

    for label, test in STRATA:
        if len(chosen) >= size:
            break
        pool = [c for c in candidates if test(c)]
        unpicked = [c for c in pool if key(c) not in reasons]
        if unpicked:
            c = rng.choice(unpicked)
            chosen.append(c)
            reasons[key(c)] = [label]
        elif pool:
            for c in pool:
                if key(c) in reasons:
                    reasons[key(c)].append(label)
                    break

    rest = [c for c in candidates if key(c) not in reasons]
    rng.shuffle(rest)
    for c in rest[: max(0, size - len(chosen))]:
        chosen.append(c)
        reasons[key(c)] = ["random"]

    return [(c, reasons[key(c)]) for c in chosen]


def to_row(c, why):
    env, pf = _env(c), _pf(c)
    ai = c.get("ai_assessment") or {}
    disc = c.get("discrepancy") or {}
    cve = env.get("CVE_ID") or ""
    published = env.get("Published_Date")
    return {
        "cve_id": cve,
        "title": env.get("Title") or "",
        "why_sampled": "; ".join(why),
        "recency": recency_label(published),
        "recheck_schedule": schedule_text(published),
        "source_url": env.get("Source_URL") or "",
        "nvd_url": f"https://nvd.nist.gov/vuln/detail/{cve}" if cve else "",
        "system_in_scope": pf.get("is_in_scope"),
        "system_category": pf.get("category") or "",
        "system_scope_reason": pf.get("reason") or "",
        "system_ai_severity": ai.get("severity_score", ""),
        "official_cvss": env.get("CVSS") if env.get("CVSS") is not None else "none yet",
        "system_priority_score": c.get("priority_score", ""),
        "system_discrepancy": disc.get("is_discrepancy", ""),
        "system_poc_urls": " | ".join(env.get("PoC_URLs") or []) or "none found",
        "system_change_status": env.get("Change_Status") or "",
        "system_change_summary": env.get("Change_Summary") or "",
        **{k: "" for k in CHECKS},
        "reviewer_notes": "",
    }


def cmd_sample(args):
    candidates = load_candidates(args.input)
    if not candidates:
        print(f"No triaged items in {args.input}. Run run_triage.py first.")
        return 1
    sample = pick_sample(candidates, args.size, args.seed)
    args.out_dir.mkdir(parents=True, exist_ok=True)
    out = args.out_dir / f"manual_check_{datetime.now(timezone.utc):%Y%m%d}.csv"
    # utf-8-sig so Excel shows non-ASCII titles correctly
    with open(out, "w", newline="", encoding="utf-8-sig") as fh:
        writer = csv.DictWriter(fh, fieldnames=COLUMNS)
        writer.writeheader()
        for c, why in sample:
            writer.writerow(to_row(c, why))
    print(f"Wrote {len(sample)} items to {out}")
    print("Fill the reviewer_* columns with Y, N or NA, then run:")
    print(f"  python Backend/run_manual_check.py score \"{out}\"")
    return 0


def score_rows(rows):
    """Per-check counts and the list of disagreements (N answers)."""
    results, misses, blanks = {}, [], 0
    for check in CHECKS:
        y = n = 0
        for r in rows:
            v = (r.get(check) or "").strip().upper()
            if v in ("Y", "YES"):
                y += 1
            elif v in ("N", "NO"):
                n += 1
                misses.append((r.get("cve_id", ""), CHECKS[check], (r.get("reviewer_notes") or "").strip()))
            elif v == "":
                blanks += 1
        results[check] = (y, n)
    return results, misses, blanks


def cmd_score(args):
    with open(args.worksheet, encoding="utf-8-sig", newline="") as fh:
        rows = list(csv.DictReader(fh))
    results, misses, blanks = score_rows(rows)
    print(f"Manual check of {len(rows)} items ({args.worksheet.name})\n")
    for check, (y, n) in results.items():
        total = y + n
        pct = f"{100 * y / total:.0f}%" if total else "n/a"
        print(f"  {CHECKS[check]:<52} {y}/{total} correct ({pct})")
    if blanks:
        print(f"\n  {blanks} reviewer cells are still empty.")
    if misses:
        print("\nWhere the system was wrong:")
        for cve, check, note in misses:
            print(f"  - {cve}: {check}" + (f" ({note})" if note else ""))
    else:
        print("\nNo disagreements recorded.")
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description="GroundedCVE manual spot-check helper")
    sub = parser.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("sample", help="pick items and write a worksheet CSV")
    s.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    s.add_argument("--size", type=int, default=12)
    s.add_argument("--seed", type=int, default=None, help="fix the sample so others can reproduce it")
    s.add_argument("--out-dir", type=Path, default=DEFAULT_OUT_DIR)
    s.set_defaults(func=cmd_sample)

    sc = sub.add_parser("score", help="score a filled-in worksheet")
    sc.add_argument("worksheet", type=Path)
    sc.set_defaults(func=cmd_score)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
