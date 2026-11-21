"""
Offline tests for the NVD collector: it must return the newest CVEs in the
7-day window, not the oldest, and skip rejected records.
"""
import json
import unittest
from unittest import mock

from Backend.ingestion.collectors.nvd import NvdCollector


def _cve(n: int, published: str, status: str = "Analyzed") -> dict:
    return {"cve": {
        "id": f"CVE-2026-{1000 + n}",
        "published": published,
        "vulnStatus": status,
        "descriptions": [{"lang": "en", "value": f"SQL injection in product {n}"}],
        "metrics": {}, "weaknesses": [], "configurations": [], "references": [],
    }}


# A 7-day window of 30 CVEs, oldest first, as NVD returns it
WINDOW = [_cve(i, f"2026-11-{14 + i // 5:02d}T{i % 5:02d}:00:00.000") for i in range(30)]


def fake_fetch(url, headers=None, timeout=None):
    from urllib.parse import urlparse, parse_qs
    q = {k: v[0] for k, v in parse_qs(urlparse(url).query).items()}
    start, size = int(q["startIndex"]), int(q["resultsPerPage"])
    return json.dumps({"totalResults": len(WINDOW), "vulnerabilities": WINDOW[start:start + size]})


class TestNvdNewestFirst(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch("Backend.ingestion.collectors.nvd.fetch_url", side_effect=fake_fetch)
        self.fetch = patcher.start()
        self.addCleanup(patcher.stop)
        sleeper = mock.patch("Backend.ingestion.collectors.nvd.time.sleep")
        sleeper.start()
        self.addCleanup(sleeper.stop)

    def test_returns_newest_cves_first(self):
        items = NvdCollector().collect(limit=5)
        self.assertEqual([e.CVE_ID for e in items],
                         ["CVE-2026-1029", "CVE-2026-1028", "CVE-2026-1027", "CVE-2026-1026", "CVE-2026-1025"])

    def test_asks_for_the_end_of_the_window(self):
        NvdCollector().collect(limit=5)
        last_url = self.fetch.call_args_list[-1].args[0]
        self.assertIn("startIndex=20", last_url)  # 30 in window, 10 fetched (twice the limit)

    def test_skips_rejected_records(self):
        WINDOW.append(_cve(99, "2026-11-20T23:00:00.000", status="Rejected"))
        try:
            items = NvdCollector().collect(limit=3)
        finally:
            WINDOW.pop()
        self.assertNotIn("CVE-2026-1099", [e.CVE_ID for e in items])
        self.assertEqual(len(items), 3)

    def test_small_window_returns_everything(self):
        items = NvdCollector().collect(limit=50)
        self.assertEqual(len(items), 30)
        self.assertEqual(items[0].CVE_ID, "CVE-2026-1029")


if __name__ == "__main__":
    unittest.main()
