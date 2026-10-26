"""
Tests for the age-based re-check policy: tiered check frequency, the one-year
freeze, and date-free recency labels.
"""
import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from Backend.ingestion.change_tracker import UNCHANGED, UPDATED, apply_change_tracking
from Backend.ingestion.models import SourceType, StagingEnvelope
from Backend.ingestion.pipeline import IngestionPipeline
from Backend.ingestion.recheck_policy import is_due, is_frozen, recency_label, recheck_interval_days
from Backend.ingestion.utils import compute_content_hash

NOW = datetime(2026, 10, 27, 9, 0, tzinfo=timezone.utc)


def published(days_ago):
    return (NOW - timedelta(days=days_ago)).isoformat()


def make_env(cve, days_old, raw=None, **kw):
    raw = raw or f"Remote code execution in {cve}."
    fields = dict(
        Item_ID=f"nvd-{cve.lower()}", Source_Type=SourceType.NVD, Title=cve,
        Source_URL=f"https://nvd.nist.gov/vuln/detail/{cve}", Published_Date=published(days_old),
        Ingested_At=NOW.isoformat(), Content_Hash=compute_content_hash(raw), Raw_Content=raw, CVE_ID=cve,
    )
    fields.update(kw)
    return StagingEnvelope(**fields)


class TestPolicy(unittest.TestCase):
    def test_check_frequency_drops_with_age(self):
        self.assertEqual(recheck_interval_days(published(3), NOW), 1)
        self.assertEqual(recheck_interval_days(published(60), NOW), 30)
        self.assertEqual(recheck_interval_days(published(300), NOW), 90)
        self.assertIsNone(recheck_interval_days(published(400), NOW))

    def test_one_to_six_month_old_cve_is_not_checked_daily_or_weekly(self):
        pub = published(90)
        self.assertFalse(is_due(pub, (NOW - timedelta(days=1)).isoformat(), NOW))
        self.assertFalse(is_due(pub, (NOW - timedelta(days=7)).isoformat(), NOW))
        self.assertTrue(is_due(pub, (NOW - timedelta(days=30)).isoformat(), NOW))

    def test_new_cve_is_checked_every_day(self):
        self.assertTrue(is_due(published(2), (NOW - timedelta(days=1)).isoformat(), NOW))

    def test_never_checked_is_due_but_frozen_never_is(self):
        self.assertTrue(is_due(published(90), None, NOW))
        self.assertFalse(is_due(published(500), None, NOW))

    def test_freeze_boundary_is_one_year(self):
        self.assertFalse(is_frozen(published(365), NOW))
        self.assertTrue(is_frozen(published(366), NOW))

    def test_labels_have_no_dates(self):
        labels = {d: recency_label(published(d), NOW) for d in (0, 20, 60, 150, 300, 500)}
        self.assertEqual(labels, {
            0: "Recent", 20: "Past month", 60: "Past 3 months", 150: "Past 6 months",
            300: "Past year", 500: "Over a year ago",
        })
        self.assertEqual(recency_label(None, NOW), "Monitored")


class TestFreezeInChangeTracking(unittest.TestCase):
    def test_frozen_item_is_not_updated_even_if_feed_changes(self):
        old = make_env("CVE-2024-1", 500, CVSS=5.0)
        day1, _ = apply_change_tracking([old], [], now=NOW - timedelta(days=1))
        revised = make_env("CVE-2024-1", 500, raw="Completely different text.", CVSS=9.8)
        day2, counts = apply_change_tracking([revised], [e.model_copy(deep=True) for e in day1], now=NOW)
        self.assertEqual(day2[0].CVSS, 5.0)
        self.assertEqual(day2[0].Change_Status, UNCHANGED)
        self.assertEqual(counts["FROZEN"], 1)

    def test_old_item_seen_for_the_first_time_is_still_ingested(self):
        merged, counts = apply_change_tracking([make_env("CVE-2024-1", 500)], [], now=NOW)
        self.assertEqual(len(merged), 1)
        self.assertEqual(counts["NEW"], 1)

    def test_carried_over_items_are_kept_without_expiry_by_default(self):
        day1, _ = apply_change_tracking([make_env("CVE-2026-1", 3)], [], now=NOW - timedelta(days=100))
        merged, counts = apply_change_tracking([], [e.model_copy(deep=True) for e in day1], now=NOW)
        self.assertEqual(len(merged), 1)
        self.assertEqual(counts["EXPIRED"], 0)


class TestPipelineRecheck(unittest.TestCase):
    def _run(self, previous, fresh_by_cve, now_days_after=0, poc=False):
        with tempfile.TemporaryDirectory() as tmp:
            staging = Path(tmp) / "Backend" / "data" / "staging"
            staging.mkdir(parents=True)
            pipeline = IngestionPipeline(staging_dir=staging)
            feed = MagicMock(name="feed")
            feed.name = "Feed"
            feed.collect.return_value = [make_env("CVE-2026-99", 1)]
            nvd = MagicMock(name="nvd")
            nvd.fetch_by_cve_id.side_effect = lambda cve: fresh_by_cve.get(cve)
            pipeline.registry = {"feed": feed, "nvd": nvd}
            import json
            (staging / "latest_envelopes.json").write_text(
                json.dumps([e.model_dump() for e in previous]), encoding="utf-8")
            summary = pipeline.run(sources=["feed"], limit_per_source=5)
            return summary, nvd

    def _stored(self, cve, days_old, last_checked_days_ago, **kw):
        env = make_env(cve, days_old, **kw)
        stamp = (datetime.now(timezone.utc) - timedelta(days=last_checked_days_ago)).isoformat()
        env.First_Seen = env.Last_Seen = env.Last_Checked = env.Last_Changed = stamp
        return env

    def test_due_older_item_is_refetched_and_changes_are_reported(self):
        stored = self._stored("CVE-2026-5", 60, last_checked_days_ago=45, CVSS=5.0)
        fresh = make_env("CVE-2026-5", 60, CVSS=9.8)
        summary, nvd = self._run([stored], {"CVE-2026-5": fresh})
        nvd.fetch_by_cve_id.assert_called_once_with("CVE-2026-5")
        item = next(e for e in summary["envelopes"] if e.CVE_ID == "CVE-2026-5")
        self.assertEqual(item.Change_Status, UPDATED)
        self.assertIn("CVSS score: 5.0 -> 9.8", item.Change_Summary)
        self.assertEqual(summary["change_counts"]["RECHECKED"], 1)
        self.assertEqual(summary["change_counts"]["RECHECK_UPDATED"], 1)

    def test_item_checked_recently_is_skipped(self):
        stored = self._stored("CVE-2026-5", 60, last_checked_days_ago=7)
        summary, nvd = self._run([stored], {})
        nvd.fetch_by_cve_id.assert_not_called()
        self.assertEqual(summary["change_counts"]["RECHECKED"], 0)

    def test_item_over_a_year_old_is_never_refetched(self):
        stored = self._stored("CVE-2024-5", 500, last_checked_days_ago=400)
        summary, nvd = self._run([stored], {"CVE-2024-5": make_env("CVE-2024-5", 500, CVSS=9.9)})
        nvd.fetch_by_cve_id.assert_not_called()
        self.assertIn("CVE-2024-5", [e.CVE_ID for e in summary["envelopes"]])

    def test_failed_fetch_keeps_item_and_retries_next_run(self):
        stored = self._stored("CVE-2026-5", 60, last_checked_days_ago=45)
        summary, nvd = self._run([stored], {})  # fetch returns None
        item = next(e for e in summary["envelopes"] if e.CVE_ID == "CVE-2026-5")
        self.assertEqual(item.Last_Checked, stored.Last_Checked)
        self.assertEqual(summary["change_counts"]["RECHECKED"], 0)


if __name__ == "__main__":
    unittest.main()
