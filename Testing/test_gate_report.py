"""
Tests for Backend/run_gate_report.py: gate statistics on real generated cards,
re-checking published cards with the current gate, and the manual review sheet.
"""
import csv
import json
import tempfile
import unittest
from pathlib import Path

from Backend import run_gate_report as gr

RAW = "SQL injection in Acme WordPress plugin before 2.1.4 allows unauthenticated attackers to read the database."
ENV = {
    "Item_ID": "nvd-cve-2026-1", "Source_Type": "NVD", "Title": "CVE-2026-1 Acme plugin SQLi",
    "Source_URL": "https://nvd.nist.gov/vuln/detail/CVE-2026-1", "Published_Date": "2026-11-01T00:00:00Z",
    "Ingested_At": "2026-11-01T00:00:00Z", "Content_Hash": "h", "Raw_Content": RAW, "CVE_ID": "CVE-2026-1",
}
GOOD = {"mechanism": "SQL injection in the Acme WordPress plugin.", "impact": "Read the database before 2.1.4.",
        "testing_syntax": [], "remediation": "Update.", "references": []}


def record(item_id, status, attempts=1, card=GOOD, failures=()):
    return {"Item_ID": item_id, "status": status, "card": card, "chunk_ids": [f"{item_id}::t1::000"],
            "verification": {"attempts": attempts, "failures": [{"check": c} for c in failures]}}


class TestSummary(unittest.TestCase):
    def test_counts_outcomes_and_failed_checks(self):
        result = gr.summarise([
            record("a", "PASSED"), record("b", "PASSED", attempts=2),
            record("c", "QUARANTINED", attempts=2, failures=["VERSION", "VERSION", "URL"]),
            {"Item_ID": "d", "status": "ERROR"},
        ])
        self.assertEqual(result["cards_drafted"], 3)
        self.assertEqual(result["passed_after_retry"], 1)
        self.assertEqual(result["error"], 1)
        self.assertAlmostEqual(result["quarantine_rate"], 1 / 3)
        self.assertEqual(result["failures_by_check"], {"VERSION": 2, "URL": 1})

    def test_later_pass_replaces_earlier_failure(self):
        with tempfile.TemporaryDirectory() as d:
            cards, log = Path(d) / "cards.json", Path(d) / "log.jsonl"
            log.write_text(json.dumps({"Item_ID": "a", "status": "ERROR"}) + "\n", encoding="utf-8")
            cards.write_text(json.dumps([record("a", "PASSED")]), encoding="utf-8")
            self.assertEqual([r["status"] for r in gr.load_records(cards, log)], ["PASSED"])


class TestRecheck(unittest.TestCase):
    def test_flags_published_card_the_current_gate_rejects(self):
        bad = dict(GOOD, impact="Leads to remote code execution on Fortinet devices.")
        result = gr.recheck([record("nvd-cve-2026-1", "PASSED"), record("x", "PASSED", card=bad)],
                            {"nvd-cve-2026-1": ENV, "x": dict(ENV, Item_ID="x")}, [])
        self.assertEqual(result["published_cards_rechecked"], 2)
        self.assertEqual([f["Item_ID"] for f in result["now_failing"]], ["x"])
        checks = {f["check"] for f in result["now_failing"][0]["failures"]}
        self.assertEqual(checks, {"IMPACT", "VENDOR_PRODUCT"})

    def test_missing_envelope_is_skipped(self):
        result = gr.recheck([record("gone", "PASSED")], {}, [])
        self.assertEqual(result["skipped_no_envelope"], 1)


class TestWorksheet(unittest.TestCase):
    def test_round_trip(self):
        with tempfile.TemporaryDirectory() as d:
            path = gr.write_worksheet([record("a", "PASSED"), record("b", "PASSED")], size=5, out_dir=Path(d))
            with open(path, newline="", encoding="utf-8-sig") as f:
                rows = list(csv.DictReader(f))
            rows[0].update(reviewer_facts_ok="Y", reviewer_impact_ok="N")
            rows[1].update(reviewer_facts_ok="Y", reviewer_impact_ok="Y")
            with open(path, "w", newline="", encoding="utf-8-sig") as f:
                w = csv.DictWriter(f, fieldnames=list(rows[0]))
                w.writeheader()
                w.writerows(rows)
            score = gr.score_worksheet(path)
            self.assertEqual(score["cards_reviewed"], 2)
            self.assertEqual(score["manual_error_rate"], 0.5)
            self.assertEqual(score["per_check"]["reviewer_impact_ok"], {"judged": 2, "wrong": 1})


if __name__ == "__main__":
    unittest.main()
