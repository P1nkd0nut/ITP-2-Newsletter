"""
Unit and Integration Tests for GroundedCVE Newsletter Dashboard & Backend API.
Verifies REST endpoints, newsletter digest curation, channel policies, and Telegram secondary bridge.
"""
import unittest
import json
import shutil
import tempfile
from datetime import date
from pathlib import Path
from unittest import mock
from Backend.api import data_service as ds
from Backend.api import telegram_service as tg
from Backend.api.app import create_app
from Backend.api.data_service import DataService
from Backend.api.telegram_service import TelegramService


class TestDashboardAPI(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Work on a temp copy of channel_config.json so tests never touch the tracked file
        cls.tmp = tempfile.TemporaryDirectory()
        tmp_config = Path(cls.tmp.name) / "channel_config.json"
        if tg.CONFIG_FILE.exists():
            shutil.copy(tg.CONFIG_FILE, tmp_config)
        cls.config_patcher = mock.patch.object(tg, "CONFIG_FILE", tmp_config)
        cls.config_patcher.start()

        cls.app = create_app()
        cls.client = cls.app.test_client()

    @classmethod
    def tearDownClass(cls):
        cls.config_patcher.stop()
        cls.tmp.cleanup()

    def _all_items(self, query=""):
        """Collect every item across pages (page_size is capped at 100)."""
        items, page = [], 1
        while True:
            data = self.client.get(f"/api/newsletters?page={page}&page_size=100&{query}").get_json()
            items.extend(data["items"])
            if page >= data.get("total_pages", 1):
                return items
            page += 1

    def test_01_health_endpoint(self):
        """Verify API health status and channel hierarchy."""
        res = self.client.get("/api/health")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["status"], "healthy")
        self.assertEqual(data["primary_channel"], "web_dashboard")
        self.assertEqual(data["secondary_channel"], "telegram")
        self.assertGreaterEqual(data["total_evaluated"], 0)

    def test_02_stats_endpoint(self):
        """Verify KPI stats, distribution bands, and source breakdown."""
        res = self.client.get("/api/stats")
        self.assertEqual(res.status_code, 200)
        stats = res.get_json()
        self.assertIn("total_evaluated", stats)
        self.assertIn("in_scope_count", stats)
        self.assertIn("avg_priority_score", stats)
        self.assertIn("score_distribution", stats)
        self.assertIn("source_breakdown", stats)
        self.assertIn("scope_breakdown", stats)

    def test_03_newsletters_query_and_pagination(self):
        """Verify querying candidates with pagination and scope filter."""
        res = self.client.get("/api/newsletters?page=1&page_size=5")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertIn("total", data)
        self.assertIn("items", data)
        self.assertLessEqual(len(data["items"]), 5)

        # Test Web scope filter
        res_web = self.client.get("/api/newsletters?scope=WEB")
        self.assertEqual(res_web.status_code, 200)
        items_web = res_web.get_json()["items"]
        for item in items_web:
            self.assertEqual(item["pre_filter"]["category"], "WEB")

    def test_04_candidate_detail_lookup(self):
        """Verify single candidate lookup by item_id or cve_id."""
        # First get an item
        list_res = self.client.get("/api/newsletters?page_size=1")
        items = list_res.get_json()["items"]
        if items:
            item_id = items[0]["envelope"]["Item_ID"]
            detail_res = self.client.get(f"/api/newsletters/{item_id}")
            self.assertEqual(detail_res.status_code, 200)
            candidate = detail_res.get_json()
            self.assertEqual(candidate["envelope"]["Item_ID"], item_id)
            self.assertIn("priority_score", candidate)
            self.assertIn("score_breakdown", candidate)

        # Non-existent item should return 404
        not_found_res = self.client.get("/api/newsletters/non-existent-cve-99999")
        self.assertEqual(not_found_res.status_code, 404)

    def test_05_weekly_digest_curation(self):
        """Verify automated weekly newsletter digest curation."""
        res = self.client.get("/api/newsletter/digest?top_n=3")
        self.assertEqual(res.status_code, 200)
        digest = res.get_json()
        self.assertIn("title", digest)
        self.assertIn("curated_threats", digest)
        self.assertIn("markdown", digest)
        self.assertLessEqual(len(digest["curated_threats"]), 3)

    def test_06_newsletter_export_markdown_and_html(self):
        """Verify export formats for weekly report generation."""
        # Markdown export
        res_md = self.client.get("/api/newsletter/export?format=markdown")
        self.assertEqual(res_md.status_code, 200)
        self.assertEqual(res_md.mimetype, "text/markdown")
        self.assertIn(b"# GroundedCVE", res_md.data)

        # HTML export
        res_html = self.client.get("/api/newsletter/export?format=html")
        self.assertEqual(res_html.status_code, 200)
        self.assertEqual(res_html.mimetype, "text/html")
        self.assertIn(b"<!DOCTYPE html>", res_html.data)

    def test_07_channel_config_and_telegram_secondary(self):
        """Verify channel hierarchy (Dashboard: Primary, Telegram: Secondary)."""
        # Read channels
        res = self.client.get("/api/channels")
        self.assertEqual(res.status_code, 200)
        channels = res.get_json()
        self.assertEqual(channels["primary_channel"]["type"], "web_dashboard")
        self.assertEqual(channels["secondary_channel"]["type"], "telegram")

        # Update secondary Telegram settings
        update_payload = {
            "secondary_channel": {
                "min_score_threshold": 75.0,
                "notify_on_kev_only": True,
            }
        }
        res_put = self.client.put(
            "/api/channels/telegram",
            data=json.dumps(update_payload),
            content_type="application/json",
        )
        self.assertEqual(res_put.status_code, 200)
        updated = res_put.get_json()["config"]["secondary_channel"]
        self.assertEqual(updated["min_score_threshold"], 75.0)
        self.assertTrue(updated["notify_on_kev_only"])

        # Test Telegram alert verification (simulation mode without real bot token)
        test_res = self.client.post("/api/channels/telegram/test", json={})
        self.assertEqual(test_res.status_code, 200)
        self.assertTrue(test_res.get_json()["success"])

    def test_08_telegram_alert_message_formatting(self):
        """Verify that Telegram card messages format with clean HTML tags."""
        telegram_svc = TelegramService()
        sample_candidate = {
            "envelope": {
                "Item_ID": "test-cve-2026-1234",
                "CVE_ID": "CVE-2026-1234",
                "Title": "Citrix NetScaler Improper Input Validation",
                "Vendor_Product": "Citrix NetScaler",
                "CVSS": 9.8,
                "KEV_Status": True,
                "PoC_URLs": ["https://github.com/test/poc"],
            },
            "pre_filter": {"category": "WEB"},
            "ai_assessment": {
                "severity_score": 8.5,
                "offensive_impact": "Remote Code Execution",
                "reasoning": "Unauthenticated remote exploit path identified.",
            },
            "priority_score": 78.0,
        }
        msg = telegram_svc.format_alert_message(sample_candidate)
        self.assertIn("CVE-2026-1234", msg)
        self.assertIn("78.0/100.0", msg)
        self.assertIn('🔗 PoC: <a href="https://github.com/test/poc">https://github.com/test/poc</a>', msg)
        self.assertNotIn("/incident/", msg)  # no dashboard links in Telegram

    def test_09_date_range_and_sorting_query(self):
        """Verify 1-week date range preset filtering and date-based sorting."""
        # 1-week preset (past 7 days up to "today"). Pin "today" to the newest item in the
        # dataset so the test does not depend on the real date.
        dates = sorted(
            x["published_date_iso"] for x in self._all_items() if x.get("published_date_iso")
        )
        self.assertTrue(dates, "dataset has no dated items")
        anchor = date.fromisoformat(dates[-1])
        win = ds.date_windows(anchor)
        expected_week = sum(1 for d in dates if win["week_start"] <= d <= win["today"])

        real_date_windows = ds.date_windows
        pinned = lambda today=None: real_date_windows(today or anchor)
        with mock.patch.object(ds, "date_windows", pinned):
            res_week = self.client.get("/api/newsletters?date_preset=week")
            week_items = self._all_items("date_preset=week")
        self.assertEqual(res_week.status_code, 200)
        self.assertGreaterEqual(res_week.get_json()["total"], 1)
        self.assertEqual(res_week.get_json()["total"], expected_week)
        for item in week_items:
            iso_date = item.get("published_date_iso", "")
            self.assertTrue(win["week_start"] <= iso_date <= win["today"])

        # 12 Oct 2026 specific preset
        res_oct12 = self.client.get("/api/newsletters?date_preset=oct12")
        self.assertEqual(res_oct12.status_code, 200)
        oct12_data = res_oct12.get_json()
        self.assertGreaterEqual(oct12_data["total"], 2)
        for item in oct12_data["items"]:
            self.assertEqual(item.get("published_date_iso"), "2026-10-12")

        # Date sorting descending
        res_sort = self.client.get("/api/newsletters?sort_by=date&sort_order=desc")
        self.assertEqual(res_sort.status_code, 200)
        sorted_items = res_sort.get_json()["items"]
        if len(sorted_items) >= 2:
            d0 = sorted_items[0].get("envelope", {}).get("Published_Date", "")
            d1 = sorted_items[1].get("envelope", {}).get("Published_Date", "")
            self.assertGreaterEqual(d0, d1)

    def test_10_category_filtering_and_ai_breakdown(self):
        """Verify category filtering and enriched AI evaluation breakdown structure."""
        # Category query
        res_cat = self.client.get("/api/newsletters?category=Remote+Code+Execution")
        self.assertEqual(res_cat.status_code, 200)
        cat_data = res_cat.get_json()
        self.assertGreaterEqual(cat_data["total"], 1)

        # AI evaluation breakdown verification
        item = cat_data["items"][0]
        self.assertIn("standard_category", item)
        self.assertIn("published_date_formatted", item)
        self.assertIn("ai_evaluation_breakdown", item)
        ai_eval = item["ai_evaluation_breakdown"]
        self.assertIn("cisa_kev_evaluation", ai_eval)
        self.assertIn("ai_severity_evaluation", ai_eval)
        self.assertIn("poc_evaluation", ai_eval)
        self.assertIn("ai_verdict", ai_eval)


if __name__ == "__main__":
    unittest.main()
