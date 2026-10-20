"""
Tests for change tracking between ingestion runs and AI-score reuse in triage.
"""
import json
import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from Backend.ingestion.change_tracker import NEW, UNCHANGED, UPDATED, apply_change_tracking
from Backend.ingestion.models import PoCReference, SourceType, StagingEnvelope
from Backend.ingestion.pipeline import IngestionPipeline
from Backend.ingestion.utils import compute_content_hash
from Backend.triage.models import AISeverityAssessment
from Backend.triage.priority_scorer import PriorityScoringEngine, reusable_assessments

DAY1 = datetime(2026, 10, 19, 6, 0, tzinfo=timezone.utc)
DAY2 = DAY1 + timedelta(days=1)


def make_env(cve, raw=None, **kw):
    raw = raw or f"SQL injection in the web login page of {cve} lets an attacker bypass authentication via HTTP."
    fields = dict(
        Item_ID=f"nvd-{cve.lower()}", Source_Type=SourceType.NVD, Title=f"{cve} web flaw",
        Source_URL=f"https://nvd.nist.gov/vuln/detail/{cve}", Published_Date="2026-10-18T00:00:00Z",
        Ingested_At=DAY1.isoformat(), Content_Hash=compute_content_hash(raw), Raw_Content=raw, CVE_ID=cve,
    )
    fields.update(kw)
    return StagingEnvelope(**fields)


def copy(env):
    return StagingEnvelope.model_validate(env.model_dump())


class TestChangeTracking(unittest.TestCase):
    def test_first_run_marks_everything_new(self):
        merged, counts = apply_change_tracking([make_env("CVE-2026-1")], [], now=DAY1)
        self.assertEqual(merged[0].Change_Status, NEW)
        self.assertEqual(merged[0].First_Seen, DAY1.isoformat())
        self.assertEqual(counts[NEW], 1)

    def test_same_content_is_unchanged_and_keeps_first_seen(self):
        day1, _ = apply_change_tracking([make_env("CVE-2026-1")], [], now=DAY1)
        day2, counts = apply_change_tracking([make_env("CVE-2026-1")], [copy(e) for e in day1], now=DAY2)
        self.assertEqual(day2[0].Change_Status, UNCHANGED)
        self.assertEqual(day2[0].First_Seen, DAY1.isoformat())
        self.assertEqual(day2[0].Last_Seen, DAY2.isoformat())
        self.assertIsNone(day2[0].Change_Summary)
        self.assertEqual(counts[UNCHANGED], 1)

    def test_text_and_field_changes_are_described(self):
        day1, _ = apply_change_tracking([make_env("CVE-2026-1", CVSS=5.0)], [], now=DAY1)
        revised = make_env("CVE-2026-1", raw=day1[0].Raw_Content + " Exploitation is unauthenticated.", CVSS=9.8)
        day2, counts = apply_change_tracking([revised], [copy(e) for e in day1], now=DAY2)
        env = day2[0]
        self.assertEqual(env.Change_Status, UPDATED)
        self.assertEqual(env.Last_Changed, DAY2.isoformat())
        self.assertIn("CVSS score: 5.0 -> 9.8", env.Change_Summary)
        text_change = [c for c in env.Change_Summary if c.startswith("Source text changed")]
        self.assertTrue(text_change)
        self.assertIn("unauthenticated", text_change[0])
        self.assertEqual(counts[UPDATED], 1)

    def test_reordered_lists_are_not_an_update(self):
        day1, _ = apply_change_tracking(
            [make_env("CVE-2026-1", Vendor_Product="npm:a, npm:b", Affected_Versions=["< 1.0", ">= 2.0, < 2.1"])], [], now=DAY1
        )
        day2, _ = apply_change_tracking(
            [make_env("CVE-2026-1", Vendor_Product="npm:b, npm:a", Affected_Versions=[">= 2.0, < 2.1", "< 1.0"])],
            [copy(e) for e in day1], now=DAY2,
        )
        self.assertEqual(day2[0].Change_Status, UNCHANGED)

    def test_new_poc_counts_as_update(self):
        day1, _ = apply_change_tracking([make_env("CVE-2026-1")], [], now=DAY1)
        poc = PoCReference(url="https://github.com/x/CVE-2026-1", source="GitHub repository search", matched_on="repo name")
        day2, _ = apply_change_tracking(
            [make_env("CVE-2026-1", PoC_URLs=[poc.url], PoC_Details=[poc])], [copy(e) for e in day1], now=DAY2
        )
        self.assertEqual(day2[0].Change_Status, UPDATED)
        self.assertEqual(day2[0].Change_Summary, ["new PoC link: https://github.com/x/CVE-2026-1"])

    def test_failed_poc_search_does_not_lose_known_pocs(self):
        poc = PoCReference(url="https://github.com/x/CVE-2026-1", source="GitHub repository search", matched_on="repo name")
        day1, _ = apply_change_tracking([make_env("CVE-2026-1", PoC_URLs=[poc.url], PoC_Details=[poc])], [], now=DAY1)
        # Day 2 GitHub search was rate-limited, so the fresh envelope has no PoCs
        day2, _ = apply_change_tracking([make_env("CVE-2026-1")], [copy(e) for e in day1], now=DAY2)
        self.assertEqual(day2[0].Change_Status, UNCHANGED)
        self.assertEqual(day2[0].PoC_URLs, [poc.url])
        self.assertEqual(day2[0].PoC_Details[0].matched_on, "repo name")

    def test_items_missing_from_feed_are_carried_over_until_expiry(self):
        day1, _ = apply_change_tracking([make_env("CVE-2026-1"), make_env("CVE-2026-2")], [], now=DAY1)
        day2, counts = apply_change_tracking([make_env("CVE-2026-2")], [copy(e) for e in day1], now=DAY2, retain_days=30)
        ids = {e.CVE_ID: e for e in day2}
        self.assertIn("CVE-2026-1", ids)
        self.assertEqual(ids["CVE-2026-1"].Change_Status, UNCHANGED)
        self.assertEqual(ids["CVE-2026-1"].Last_Seen, DAY1.isoformat())
        self.assertEqual(counts["CARRIED_OVER"], 1)

        later = DAY1 + timedelta(days=31)
        day32, counts = apply_change_tracking([make_env("CVE-2026-2")], [copy(e) for e in day2], now=later, retain_days=30)
        self.assertEqual([e.CVE_ID for e in day32], ["CVE-2026-2"])
        self.assertEqual(counts["EXPIRED"], 1)

    def test_same_cve_from_two_sources_is_tracked_separately(self):
        kev = make_env("CVE-2026-1", Item_ID="cisa-kev-cve-2026-1", Source_Type=SourceType.CISA_KEV)
        merged, counts = apply_change_tracking([make_env("CVE-2026-1"), kev], [], now=DAY1)
        self.assertEqual(len(merged), 2)
        self.assertEqual(counts[NEW], 2)


class TestPipelineUsesPreviousFile(unittest.TestCase):
    def _pipeline(self, staging, items):
        pipeline = IngestionPipeline(staging_dir=staging)
        collector = MagicMock(name="fake")
        collector.name = "Fake feed"
        collector.collect.return_value = items
        pipeline.registry = {"fake": collector}
        return pipeline

    def test_second_run_compares_with_latest_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            staging = Path(tmp) / "Backend" / "data" / "staging"
            staging.mkdir(parents=True)
            first = self._pipeline(staging, [make_env("CVE-2026-1")]).run(limit_per_source=5)
            self.assertEqual(first["change_counts"][NEW], 1)

            second = self._pipeline(staging, [make_env("CVE-2026-1"), make_env("CVE-2026-2")]).run(limit_per_source=5)
            self.assertEqual(second["change_counts"][NEW], 1)
            self.assertEqual(second["change_counts"][UNCHANGED], 1)

            saved = json.loads((staging / "latest_envelopes.json").read_text(encoding="utf-8"))
            self.assertEqual({e["CVE_ID"]: e["Change_Status"] for e in saved}, {"CVE-2026-1": UNCHANGED, "CVE-2026-2": NEW})
            # No timestamped snapshots unless asked for
            self.assertEqual(list(staging.glob("envelopes_*.json")), [])

    def test_snapshots_are_pruned_to_keep_count(self):
        with tempfile.TemporaryDirectory() as tmp:
            staging = Path(tmp)
            for stamp in ("20260101_000000", "20260102_000000", "20260103_000000"):
                (staging / f"envelopes_{stamp}.json").write_text("[]", encoding="utf-8")
            self._pipeline(staging, [make_env("CVE-2026-1")]).run(limit_per_source=5, keep_snapshots=2)
            snapshots = sorted(p.name for p in staging.glob("envelopes_*.json"))
            self.assertEqual(len(snapshots), 2)
            self.assertEqual(snapshots[0], "envelopes_20260103_000000.json")


class TestTriageReusesScores(unittest.TestCase):
    def setUp(self):
        self.assessment = AISeverityAssessment(
            severity_score=8.0, offensive_impact="Remote Code Execution", exploitability="HIGH",
            reasoning="r", evaluated_by="openrouter/qwen/qwen-2.5-72b-instruct",
        )

    def _previous(self, env, assessment):
        evaluator = MagicMock()
        evaluator.evaluate.return_value = assessment
        return PriorityScoringEngine(ai_evaluator=evaluator).triage_batch([env])

    def test_unchanged_item_is_not_sent_to_ai_again(self):
        env = make_env("CVE-2026-1")
        cache = reusable_assessments(self._previous(copy(env), self.assessment), [env])
        self.assertIn(env.Item_ID, cache)

        evaluator = MagicMock()
        engine = PriorityScoringEngine(ai_evaluator=evaluator, kev_catalog={"CVE-2026-1"})
        [candidate] = engine.triage_batch([env], cached_ai=cache)
        evaluator.evaluate.assert_not_called()
        self.assertEqual(candidate.ai_assessment.severity_score, 8.0)
        # Score is still recomputed with today's KEV data
        self.assertGreater(candidate.score_breakdown["cisa_kev_points"], 0)

    def test_changed_text_is_rescored(self):
        old = make_env("CVE-2026-1")
        new = make_env("CVE-2026-1", raw=old.Raw_Content + " Now exploited in the wild.")
        self.assertEqual(reusable_assessments(self._previous(old, self.assessment), [new]), {})

    def test_heuristic_fallback_scores_are_retried(self):
        env = make_env("CVE-2026-1")
        fallback = self.assessment.model_copy(update={"evaluated_by": "heuristic_engine"})
        self.assertEqual(reusable_assessments(self._previous(copy(env), fallback), [env]), {})


if __name__ == "__main__":
    unittest.main()
