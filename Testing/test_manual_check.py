"""
Tests for the manual spot-check sampler and scorer.
"""
import csv
import json
import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from Backend import run_manual_check as mc


def cand(cve, days_old, in_scope=True, poc=False, kev=False, disc=False, status="NEW"):
    pub = (datetime.now(timezone.utc) - timedelta(days=days_old)).isoformat()
    return {
        "envelope": {
            "Item_ID": f"nvd-{cve.lower()}", "CVE_ID": cve, "Title": cve, "Source_URL": "https://example.org",
            "Published_Date": pub, "PoC_URLs": [f"https://github.com/x/{cve}"] if poc else None,
            "KEV_Status": kev, "CVSS": 7.5, "Change_Status": status,
        },
        "pre_filter": {"is_in_scope": in_scope, "category": "WEB" if in_scope else "OUT_OF_SCOPE", "reason": "r"},
        "ai_assessment": {"severity_score": 7.0},
        "discrepancy": {"is_discrepancy": disc},
        "priority_score": 50,
    }


CANDIDATES = [
    cand("CVE-1", 3, poc=True, kev=True),
    cand("CVE-2", 60, in_scope=False),
    cand("CVE-3", 200, disc=True, status="UPDATED"),
    cand("CVE-4", 500),
] + [cand(f"CVE-R{i}", 10) for i in range(20)]


class TestSample(unittest.TestCase):
    def test_covers_each_group_and_respects_size(self):
        sample = mc.pick_sample(CANDIDATES, 8, seed=1)
        self.assertEqual(len(sample), 8)
        cves = {c["envelope"]["CVE_ID"] for c, _ in sample}
        # the single out-of-scope, discrepancy and frozen items must be included
        self.assertTrue({"CVE-2", "CVE-3", "CVE-4"} <= cves)
        self.assertEqual(len(cves), 8)

    def test_seed_is_reproducible(self):
        a = [c["envelope"]["CVE_ID"] for c, _ in mc.pick_sample(CANDIDATES, 6, seed=7)]
        b = [c["envelope"]["CVE_ID"] for c, _ in mc.pick_sample(CANDIDATES, 6, seed=7)]
        self.assertEqual(a, b)

    def test_row_uses_relative_age_and_schedule(self):
        row = mc.to_row(cand("CVE-4", 500), ["x"])
        self.assertEqual(row["recheck_schedule"], "frozen (not updated)")
        self.assertEqual(row["recency"], "Over a year ago")
        self.assertEqual(mc.to_row(cand("CVE-1", 3), [])["recheck_schedule"], "every run")


class TestEndToEnd(unittest.TestCase):
    def test_sample_then_score(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            inp = tmp / "triaged.json"
            inp.write_text(json.dumps(CANDIDATES), encoding="utf-8")
            self.assertEqual(mc.main(["sample", "--input", str(inp), "--size", "5", "--seed", "3",
                                      "--out-dir", str(tmp)]), 0)
            sheet = next(tmp.glob("manual_check_*.csv"))
            with open(sheet, encoding="utf-8-sig", newline="") as fh:
                rows = list(csv.DictReader(fh))
            self.assertEqual(len(rows), 5)
            for r in rows:
                for k in mc.CHECKS:
                    r[k] = "Y"
            rows[0]["reviewer_poc_ok"] = "N"
            rows[0]["reviewer_notes"] = "wrong repo"
            results, misses, blanks = mc.score_rows(rows)
            self.assertEqual(results["reviewer_poc_ok"], (4, 1))
            self.assertEqual(results["reviewer_scope_ok"], (5, 0))
            self.assertEqual(blanks, 0)
            self.assertEqual(misses[0][2], "wrong repo")


if __name__ == "__main__":
    unittest.main()
