"""
Tests for the incident reader page and the Telegram weekly digest.
"""
import json
import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

import requests

from Backend.api import telegram_service as tg
from Backend.api.app import create_app
from Backend.api.data_service import data_service


def days_ago(n):
    return (datetime.now(timezone.utc) - timedelta(days=n)).isoformat()


def make_candidate(item_id, score, category="WEB", published=None, **env):
    return {
        "envelope": {"Item_ID": item_id, "Title": f"Title {item_id}", "Published_Date": published or days_ago(1), **env},
        "pre_filter": {"category": category, "is_in_scope": category in ("WEB", "MOBILE")},
        "priority_score": score,
        "recency_label": "Recent",
        "in_depth": {"brief_summary": f"Summary for {item_id}."},
        "grounded_card": {"mechanism": f"Summary for {item_id}.", "impact": "", "checks_run": 3},
    }


class FakeResponse:
    def __init__(self, status_code, body=None):
        self.status_code = status_code
        self._body = body or {}
        self.text = json.dumps(self._body)

    def json(self):
        return self._body


class TestReaderPage(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = create_app().test_client()

    def test_incident_page_served_for_known_item(self):
        item_id = data_service.get_all_candidates()[0]["envelope"]["Item_ID"]
        res = self.client.get(f"/incident/{item_id}")
        self.assertEqual(res.status_code, 200)
        self.assertIn(b"Grounded Threat News", res.data)
        self.assertIn(b"/api/newsletters/", res.data)

    def test_unknown_incident_returns_404(self):
        res = self.client.get("/incident/does-not-exist-123")
        self.assertEqual(res.status_code, 404)
        self.assertIn(b"Incident not found", res.data)


class TestTokenStaysInEnv(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.config_file = Path(self.tmp.name) / "channel_config.json"
        patcher = mock.patch.object(tg, "CONFIG_FILE", self.config_file)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(self.tmp.cleanup)
        self.service = tg.TelegramService()

    @mock.patch.dict(os.environ, {"TELEGRAM_BOT_TOKEN": "123:SECRET"})
    def test_config_reports_token_set_but_never_the_token(self):
        cfg = self.service.get_config()
        self.assertTrue(cfg["secondary_channel"]["bot_token_set"])
        self.assertNotIn("SECRET", json.dumps(cfg))

    def test_update_ignores_token_and_does_not_save_it(self):
        self.service.update_config({"secondary_channel": {"bot_token": "123:LEAKED", "chat_id": "42"}})
        saved = self.config_file.read_text(encoding="utf-8")
        self.assertNotIn("LEAKED", saved)
        self.assertNotIn("bot_token", saved)
        self.assertEqual(json.loads(saved)["secondary_channel"]["chat_id"], "42")

    @mock.patch.dict(os.environ, {"TELEGRAM_CHAT_ID": "-100999"})
    def test_env_chat_id_overrides_saved_one(self):
        self.service.update_config({"secondary_channel": {"chat_id": "42"}})
        self.assertEqual(self.service.chat_id(), "-100999")


class TestDigestFormatting(unittest.TestCase):
    @mock.patch.dict(os.environ, {"BASE_URL": "http://192.168.1.20:5000/"})
    def test_item_links_to_its_reader_page(self):
        msg = tg.format_digest_item(make_candidate("nvd-cve-2026-1", 80.0, CVE_ID="CVE-2026-1"), 1)
        self.assertIn('href="http://192.168.1.20:5000/incident/nvd-cve-2026-1"', msg)
        self.assertIn("CVE-2026-1", msg)
        self.assertIn("Priority 80/100", msg)

    def test_source_text_is_html_escaped(self):
        c = make_candidate("x-1", 50.0, Title="<script>alert(1)</script> & co")
        c["in_depth"] = {"brief_summary": "Use <b>bold</b> & <a href='x'>"}
        c["grounded_card"]["mechanism"] = c["in_depth"]["brief_summary"]
        msg = tg.format_digest_item(c, 1)
        self.assertNotIn("<script>", msg)
        self.assertIn("&lt;script&gt;", msg)
        self.assertIn("&amp; co", msg)
        self.assertNotIn("<b>bold</b>", msg)

    def test_long_text_fits_telegram_limit(self):
        c = make_candidate("x-2", 50.0, Title="T" * 5000)
        c["in_depth"] = {"brief_summary": "<&>" * 5000}
        c["grounded_card"]["mechanism"] = c["in_depth"]["brief_summary"]
        for msg in [tg.format_digest_item(c, 1), tg.format_digest_header([c])]:
            self.assertLessEqual(len(msg), tg.MAX_MESSAGE_CHARS)

    def test_digest_picks_recent_in_scope_items_by_priority(self):
        candidates = [
            make_candidate("low", 30.0),
            make_candidate("high", 90.0, category="MOBILE"),
            make_candidate("old", 99.0, published=days_ago(30)),
            make_candidate("out", 95.0, category="OUT_OF_SCOPE"),
        ]
        messages = tg.build_weekly_digest(candidates, days=7, top_n=10)
        self.assertEqual(len(messages), 3)  # header + high + low
        self.assertIn("Weekly Brief", messages[0])
        self.assertIn("1 Web, 1 Mobile", messages[0])
        self.assertIn("/incident/high", messages[1])
        self.assertIn("/incident/low", messages[2])

    def test_digest_leaves_out_items_without_a_verified_card(self):
        unverified = make_candidate("unverified", 99.0)
        unverified["grounded_card"] = None
        messages = tg.build_weekly_digest([unverified, make_candidate("ok", 10.0)], days=7)
        self.assertEqual(len(messages), 2)
        self.assertIn("/incident/ok", messages[1])
        self.assertNotIn("unverified", "".join(messages))

    def test_digest_summary_comes_from_the_verified_card(self):
        c = make_candidate("x-3", 50.0)
        c["grounded_card"]["mechanism"] = "Grounded mechanism text."
        self.assertIn("Grounded mechanism text.", tg.format_digest_item(c, 1))

    def test_empty_week_still_sends_header(self):
        messages = tg.build_weekly_digest([make_candidate("old", 99.0, published=days_ago(30))], days=7)
        self.assertEqual(len(messages), 1)
        self.assertIn("No new Web or Mobile incidents", messages[0])


class TestSending(unittest.TestCase):
    @mock.patch.object(tg.time, "sleep")
    @mock.patch.object(tg.requests, "post")
    def test_retries_after_429(self, post, sleep):
        post.side_effect = [FakeResponse(429, {"parameters": {"retry_after": 3}}), FakeResponse(200, {"ok": True})]
        self.assertEqual(tg.send_message("123:SECRET", "42", "hi"), {"ok": True})
        sleep.assert_called_once_with(3)
        self.assertEqual(post.call_args.kwargs["json"]["parse_mode"], "HTML")

    @mock.patch.object(tg.requests, "post")
    def test_network_error_hides_token(self, post):
        post.side_effect = requests.ConnectionError("Max retries exceeded with url: /bot123:SECRET/sendMessage")
        result = tg.send_message("123:SECRET", "42", "hi")
        self.assertFalse(result["ok"])
        self.assertNotIn("SECRET", result["error"])

    @mock.patch.object(tg.requests, "post")
    def test_api_error_is_reported_as_failure(self, post):
        post.return_value = FakeResponse(400, {"description": "Bad Request: chat not found"})
        result = tg.send_message("123:SECRET", "42", "hi")
        self.assertFalse(result["ok"])
        self.assertIn("chat not found", result["error"])

    @mock.patch.dict(os.environ, {"TELEGRAM_BOT_TOKEN": "123:SECRET", "TELEGRAM_CHAT_ID": "42"})
    @mock.patch.object(tg.time, "sleep")
    @mock.patch.object(tg.requests, "post")
    def test_digest_stops_at_first_failure_and_pauses_between_messages(self, post, sleep):
        post.side_effect = [FakeResponse(200), FakeResponse(400, {"description": "boom"}), FakeResponse(200)]
        result = tg.telegram_service.send_digest(["a", "b", "c"])
        self.assertEqual(result["sent"], 1)
        self.assertIn("boom", result["error"])
        self.assertEqual(post.call_count, 2)
        sleep.assert_called_with(tg.SEND_PAUSE_SECONDS)

    @mock.patch.dict(os.environ, {"TELEGRAM_BOT_TOKEN": ""})
    def test_digest_refuses_without_token(self):
        result = tg.telegram_service.send_digest(["a"])
        self.assertEqual(result["sent"], 0)
        self.assertIn("TELEGRAM_BOT_TOKEN", result["error"])


if __name__ == "__main__":
    unittest.main()
