"""
Offline tests for the Apple security releases collector: one envelope per
advisory, dated by Apple's release date rather than the run time.

Run:
    python -m pytest Testing/test_apple_collector.py -v
"""
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from Backend.ingestion.collectors import mobile_sources as ms
from Backend.ingestion.collectors.mobile_sources import AppleSecurityCollector, parse_apple_index

INDEX_HTML = """
<table>
  <tr><th>Name and information link</th><th>Available for</th><th>Release date</th></tr>
  <tr><td><p><a href="https://support.apple.com/en-us/149230">iOS 27.2 and iPadOS 27.2</a></p></td>
      <td><p>iPhone 11 and later</p></td><td><p>26 Oct 2026</p></td></tr>
  <tr><td><p>tvOS 26.6.1</p><p>This update has no published CVE entries.</p></td>
      <td><p>Apple TV HD</p></td><td><p>26 Oct 2026</p></td></tr>
  <tr><td><p><a href="/en-us/149100">Safari 27.1</a></p></td>
      <td><p>macOS Tahoe</p></td><td><p>14 Sep 2026</p></td></tr>
  <tr><td><p><a href="https://support.apple.com/kb/HT201222">Older layout</a></p></td>
      <td><p>Mac</p></td><td><p>Preinstalled</p></td></tr>
</table>
"""

ADVISORY_HTML = {
    "https://support.apple.com/en-us/149230": "<p>WebKit</p><p>Impact: Processing web content may lead to code execution</p>"
                                              "<p>CVE-2026-86971: an anonymous researcher</p><p>CVE-2026-112413</p>",
    "https://support.apple.com/en-us/149100": "<p>Safari</p><p>CVE-2026-50001</p>",
}


def fake_fetch(url, **kwargs):
    if url == ms.APPLE_SECURITY_RELEASES_URL:
        return INDEX_HTML
    if url in ADVISORY_HTML:
        return ADVISORY_HTML[url]
    raise OSError(f"unexpected url {url}")


class TestAppleIndexParsing(unittest.TestCase):
    def test_one_entry_per_linked_advisory_with_release_date(self):
        rows = parse_apple_index(INDEX_HTML)
        self.assertEqual([r["advisory_id"] for r in rows], ["149230", "149100"])
        self.assertEqual(rows[0]["published"], "2026-10-26T00:00:00+00:00")
        self.assertEqual(rows[1]["url"], "https://support.apple.com/en-us/149100")
        self.assertEqual(rows[0]["available_for"], "iPhone 11 and later")

    def test_date_formats(self):
        self.assertEqual(ms.parse_apple_release_date("09 Jan 2024"), "2024-01-09T00:00:00+00:00")
        self.assertEqual(ms.parse_apple_release_date("January 9, 2024"), "2024-01-09T00:00:00+00:00")
        self.assertIsNone(ms.parse_apple_release_date("Preinstalled"))


class TestAppleCollector(unittest.TestCase):
    def test_collects_each_advisory_as_its_own_item(self):
        with mock.patch.object(ms, "fetch_url", side_effect=fake_fetch):
            envs = AppleSecurityCollector().collect()
        self.assertEqual([e.Item_ID for e in envs], ["apple-149230", "apple-149100"])
        ios = envs[0]
        self.assertEqual(ios.Published_Date, "2026-10-26T00:00:00+00:00")
        self.assertNotEqual(ios.Published_Date, ios.Ingested_At)
        self.assertEqual(ios.Source_URL, "https://support.apple.com/en-us/149230")
        self.assertEqual(ios.Raw_Content, ADVISORY_HTML[ios.Source_URL])
        self.assertEqual(ios.Extra_Metadata["cve_ids"], ["CVE-2026-112413", "CVE-2026-86971"])
        self.assertIn("iOS 27.2", ios.Title)

    def test_limit_applies_to_newest_advisories(self):
        with mock.patch.object(ms, "fetch_url", side_effect=fake_fetch) as fetch:
            envs = AppleSecurityCollector().collect(limit=1)
        self.assertEqual([e.Item_ID for e in envs], ["apple-149230"])
        self.assertEqual(fetch.call_count, 2)  # index + one advisory

    def test_advisory_that_fails_to_load_is_skipped(self):
        def flaky(url, **kwargs):
            if url.endswith("149230"):
                raise OSError("429")
            return fake_fetch(url)
        with mock.patch.object(ms, "fetch_url", side_effect=flaky):
            envs = AppleSecurityCollector().collect()
        self.assertEqual([e.Item_ID for e in envs], ["apple-149100"])

    def test_index_failure_returns_nothing(self):
        with mock.patch.object(ms, "fetch_url", side_effect=OSError("down")):
            self.assertEqual(AppleSecurityCollector().collect(), [])


if __name__ == "__main__":
    unittest.main()
