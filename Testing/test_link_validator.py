"""
Unit tests for the link health validator, run against a local HTTP server.
"""
import os
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from Backend.api import link_validator as lv


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _respond(self, send_body: bool):
        path = self.path
        if path == "/":
            code = 200
        elif path == "/ok":
            code = 200
        elif path == "/gone":
            code = 404
        elif path == "/no-head" and self.command == "HEAD":
            code = 405
        elif path == "/no-head":
            code = 200
        elif path == "/head-404-get-ok" and self.command == "HEAD":
            code = 404
        elif path == "/head-404-get-ok":
            code = 200
        elif path == "/forbidden":
            code = 403
        elif path == "/flaky":
            code = 503
        elif path == "/old-advisory":
            self.send_response(301)
            self.send_header("Location", "/")
            self.end_headers()
            return
        else:
            code = 404
        self.send_response(code)
        self.send_header("Content-Length", "2")
        self.end_headers()
        if send_body:
            self.wfile.write(b"ok")

    def do_HEAD(self):
        self._respond(send_body=False)

    def do_GET(self):
        self._respond(send_body=True)


class TestLinkValidator(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Never route requests to the local test server through a proxy
        for key in ("no_proxy", "NO_PROXY"):
            os.environ[key] = ",".join(filter(None, [os.environ.get(key), "127.0.0.1", "localhost"]))
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        cls.base = f"http://127.0.0.1:{cls.server.server_address[1]}"
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        cls._orig_delay = lv.RETRY_DELAY_SECONDS
        lv.RETRY_DELAY_SECONDS = 0

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        lv.RETRY_DELAY_SECONDS = cls._orig_delay

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.validator = lv.LinkValidator(cache_file=Path(self.tmp.name) / "cache.json", archive_lookup=False)

    def tearDown(self):
        self.tmp.cleanup()

    def check(self, path, **kw):
        return self.validator.check_single_link(self.base + path, **kw)

    def test_live_link(self):
        r = self.check("/ok")
        self.assertEqual(r["state"], lv.LIVE)
        self.assertTrue(r["is_working"])

    def test_404_is_dead(self):
        r = self.check("/gone")
        self.assertEqual(r["state"], lv.DEAD)
        self.assertFalse(r["is_working"])

    def test_head_rejected_falls_back_to_get(self):
        self.assertEqual(self.check("/no-head")["state"], lv.LIVE)

    def test_head_404_is_confirmed_with_get(self):
        self.assertEqual(self.check("/head-404-get-ok")["state"], lv.LIVE)

    def test_403_is_blocked_not_live(self):
        r = self.check("/forbidden")
        self.assertEqual(r["state"], lv.BLOCKED)
        self.assertIsNone(r["is_working"])

    def test_redirect_to_homepage_is_moved(self):
        r = self.check("/old-advisory")
        self.assertEqual(r["state"], lv.MOVED)
        self.assertFalse(r["is_working"])

    def test_server_error_is_temporary_then_dead(self):
        first = self.check("/flaky")
        self.assertEqual(first["state"], lv.TEMPORARY)
        self.assertIsNone(first["is_working"])
        second = self.check("/flaky", force_refresh=True)
        self.assertEqual(second["state"], lv.DEAD)

    def test_temporary_errors_expire_sooner(self):
        self.check("/flaky")
        self.validator._cache[self.base + "/flaky"]["last_checked_ts"] = time.time() - 31 * 60
        self.assertFalse(self.validator.is_cache_valid(self.base + "/flaky"))
        self.check("/ok")
        self.validator._cache[self.base + "/ok"]["last_checked_ts"] = time.time() - 31 * 60
        self.assertTrue(self.validator.is_cache_valid(self.base + "/ok"))

    def test_offline_mode_does_not_fake_a_result(self):
        r = self.check("/gone", allow_network=False)
        self.assertEqual(r["state"], lv.UNCHECKED)
        self.assertIsNone(r["is_working"])
        self.assertNotIn(self.base + "/gone", self.validator._cache)

    def test_offline_mode_returns_last_real_result(self):
        self.check("/gone")
        r = self.check("/gone", allow_network=False)
        self.assertEqual(r["state"], lv.DEAD)

    def test_batch_and_stats(self):
        urls = [{"url": self.base + p} for p in ("/ok", "/gone", "/forbidden", "/ok")]
        results = self.validator.validate_batch(urls)
        self.assertEqual(len(results), 3)
        stats = self.validator.get_stats()
        self.assertEqual(stats["active_links"], 1)
        self.assertEqual(stats["dead_links"], 1)
        self.assertEqual(stats["blocked_links"], 1)
        self.assertEqual(stats["health_percentage"], 50.0)

    def test_legacy_placeholder_cache_entries_are_dropped(self):
        cache = Path(self.tmp.name) / "legacy.json"
        cache.write_text('{"https://x.test/a": {"status_label": "200 OK (Cataloged)", "is_working": true, "last_checked_ts": 9e12}}')
        v = lv.LinkValidator(cache_file=cache, archive_lookup=False)
        self.assertFalse(v.is_cache_valid("https://x.test/a"))

    def test_homepage_redirect_detection(self):
        self.assertTrue(lv.is_homepage_redirect("https://a.com/advisory/123", "https://a.com/"))
        self.assertTrue(lv.is_homepage_redirect("https://a.com/advisory/123", "https://a.com/en-us/"))
        self.assertFalse(lv.is_homepage_redirect("https://a.com/advisory/123", "https://a.com/advisory/123/"))
        self.assertFalse(lv.is_homepage_redirect("https://a.com/", "https://a.com/"))
        self.assertFalse(lv.is_homepage_redirect("https://a.com/x", "https://a.com/docs/x"))


if __name__ == "__main__":
    unittest.main()
