"""
Offline tests for the NVD collector: it must return the newest CVEs in the
7-day window, not the oldest, skip rejected records, and pick a CVSS score
that is comparable with the AI severity.
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


def _metric(score: float, source: str = "cna@vuldb.com", kind: str = "Secondary") -> dict:
    return {"source": source, "type": kind, "cvssData": {"baseScore": score}}


class TestCvssChoice(unittest.TestCase):
    """The official score should be NVD's own, else the CNA's v3.x base score, else v4.0."""

    def setUp(self):
        self.collector = NvdCollector()

    def test_cna_v31_preferred_over_cna_v40_with_threat_metrics(self):
        metrics = {"cvssMetricV40": [_metric(2.1)], "cvssMetricV31": [_metric(6.3)]}
        self.assertEqual(self.collector._extract_cvss(metrics), (6.3, "3.1"))

    def test_nvd_primary_score_wins(self):
        metrics = {
            "cvssMetricV40": [_metric(2.1)],
            "cvssMetricV31": [_metric(6.3), _metric(7.8, "nvd@nist.gov", "Primary")],
        }
        self.assertEqual(self.collector._extract_cvss(metrics), (7.8, "3.1"))

    def test_v40_used_when_it_is_the_only_score(self):
        self.assertEqual(self.collector._extract_cvss({"cvssMetricV40": [_metric(8.7)]}), (8.7, "4.0"))

    def test_entries_without_scores_are_ignored(self):
        metrics = {"cvssMetricV31": [{"source": "x", "type": "Secondary"}], "cvssMetricV40": [_metric(5.3)]}
        self.assertEqual(self.collector._extract_cvss(metrics), (5.3, "4.0"))
        self.assertEqual(self.collector._extract_cvss({}), (None, None))


class TestAffectedVersions(unittest.TestCase):
    def test_ranges_and_exact_versions_are_readable(self):
        from Backend.ingestion.collectors.nvd import affected_versions
        configs = [{"nodes": [{"cpeMatch": [
            {"vulnerable": True, "criteria": "cpe:2.3:a:apache:roller:*:*:*:*:*:*:*:*",
             "versionStartIncluding": "5.0.0", "versionEndExcluding": "6.1.5"},
            {"vulnerable": True, "criteria": "cpe:2.3:a:ivanti:connect_secure:22.7:r2:*:*:*:*:*:*"},
            {"vulnerable": False, "criteria": "cpe:2.3:o:linux:linux_kernel:-:*:*:*:*:*:*:*"},
        ]}]}]
        self.assertEqual(affected_versions(configs), ["Apache Roller from 5.0.0 before 6.1.5", "Ivanti Connect Secure 22.7"])
        self.assertEqual(affected_versions([]), [])

    def test_kev_items_get_versions_from_the_nvd_record(self):
        from Backend.ingestion.models import SourceType, StagingEnvelope
        from Backend.ingestion.pipeline import IngestionPipeline

        def env(item_id, source, versions=None):
            return StagingEnvelope(
                Item_ID=item_id, Source_Type=source, Title="t", Source_URL="https://example.com",
                Published_Date="2026-11-20T00:00:00+00:00", Ingested_At="2026-11-21T00:00:00+00:00",
                Content_Hash="h" + item_id, Raw_Content="{}", CVE_ID="CVE-2026-1", Affected_Versions=versions,
            )

        pipeline = IngestionPipeline()
        kev = env("kev-1", SourceType.CISA_KEV)
        with mock.patch.object(pipeline.registry["nvd"], "versions_for", return_value=["Apache Roller before 6.1.5"]) as lookup, \
                mock.patch("Backend.ingestion.pipeline.time.sleep"):
            self.assertEqual(pipeline.add_nvd_versions([kev]), 1)
        lookup.assert_called_once_with("CVE-2026-1")
        self.assertEqual(kev.Affected_Versions, ["Apache Roller before 6.1.5"])
        self.assertEqual(kev.Extra_Metadata["affected_versions_from"], "NVD record for CVE-2026-1")

        # An NVD item for the same CVE in the batch is used without a lookup
        kev2 = env("kev-2", SourceType.CISA_KEV)
        nvd = env("nvd-1", SourceType.NVD, ["Apache Roller up to 6.1.4"])
        with mock.patch.object(pipeline.registry["nvd"], "versions_for") as lookup:
            pipeline.add_nvd_versions([kev2, nvd])
        lookup.assert_not_called()
        self.assertEqual(kev2.Affected_Versions, ["Apache Roller up to 6.1.4"])

        # A fresh copy from the KEV feed keeps the looked-up versions, so it doesn't read as a change
        from Backend.ingestion.change_tracker import apply_change_tracking
        fresh = env("kev-1", SourceType.CISA_KEV)
        merged, counts = apply_change_tracking([fresh], [kev])
        self.assertEqual(merged[0].Affected_Versions, ["Apache Roller before 6.1.5"])
        self.assertEqual(counts["UNCHANGED"], 1)


if __name__ == "__main__":
    unittest.main()
