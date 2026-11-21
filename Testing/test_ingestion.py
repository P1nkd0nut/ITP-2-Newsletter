"""
Unit and Integration Tests for GroundedCVE Ingestion Architecture.
Validates staging envelope schema constraints, deterministic hashing,
and collector outputs.
"""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
import urllib.error
import urllib.request

from Backend.ingestion.models import StagingEnvelope, SourceType, PoCReference
from Backend.ingestion.utils import compute_content_hash, normalize_to_iso, get_utc_now_iso
from Backend.ingestion.collectors.cisa_kev import CisaKevCollector
from Backend.ingestion.collectors.rss_feeds import create_portswigger_collector, create_project_zero_collector
from Backend.ingestion.collectors.github_advisory import GitHubAdvisoryCollector
from Backend.ingestion.pipeline import IngestionPipeline


def _feeds_reachable() -> bool:
    """True when the live feeds can be reached, so the live tests skip cleanly offline."""
    try:
        urllib.request.urlopen("https://www.cisa.gov/", timeout=5)
        return True
    except urllib.error.HTTPError:
        return True  # the server answered, so the network works
    except Exception:
        return False


ONLINE = _feeds_reachable()


class TestStagingEnvelopeModel(unittest.TestCase):
    """Tests Pydantic StagingEnvelope schema compliance."""

    def test_valid_envelope_creation(self):
        raw_text = "Vulnerability test details in sample source."
        h = hashlib.sha256(raw_text.encode("utf-8")).hexdigest()

        envelope = StagingEnvelope(
            Item_ID="test-item-01",
            Source_Type=SourceType.NVD,
            Title="Test Vulnerability Title",
            Source_URL="https://nvd.nist.gov/vuln/detail/CVE-2024-0001",
            Published_Date="2024-01-01T00:00:00Z",
            Ingested_At="2026-09-28T12:00:00Z",
            Content_Hash=h,
            Raw_Content=raw_text,
            CVE_ID="CVE-2024-0001",
            Vendor_Product="Test Vendor Test Product",
            CVSS=8.5,
            CVSS_Version="3.1",
            CWE=["CWE-79"],
            KEV_Status=False,
            PoC_URLs=["https://github.com/poc/test"],
        )

        self.assertEqual(envelope.Item_ID, "test-item-01")
        self.assertEqual(envelope.Source_Type, SourceType.NVD)
        self.assertEqual(envelope.CVSS, 8.5)
        self.assertEqual(envelope.Content_Hash, h)
        self.assertEqual(envelope.Raw_Content, raw_text)

    def test_missing_required_field_raises_error(self):
        with self.assertRaises(Exception):
            # Missing Raw_Content and Content_Hash
            StagingEnvelope(
                Item_ID="missing-fields",
                Source_Type=SourceType.PORTSWIGGER,
                Title="Sample",
                Source_URL="https://example.com",
                Published_Date="2024-01-01T00:00:00Z",
                Ingested_At="2026-09-28T12:00:00Z",
            )

    def test_content_hashing_deterministic(self):
        content = "Exact raw proof of concept script adb shell am start..."
        h1 = compute_content_hash(content)
        h2 = compute_content_hash(content)
        self.assertEqual(h1, h2)
        self.assertEqual(len(h1), 64)  # SHA-256 hex length


@unittest.skipUnless(ONLINE, "live feeds not reachable (offline)")
class TestCollectorsLive(unittest.TestCase):
    """Smoke tests verifying collectors can fetch and format real feeds."""

    def test_cisa_kev_collector(self):
        collector = CisaKevCollector()
        items = collector.collect(limit=2)
        self.assertGreaterEqual(len(items), 1)
        first = items[0]
        self.assertEqual(first.Source_Type, SourceType.CISA_KEV)
        self.assertTrue(first.KEV_Status)
        self.assertTrue(first.CVE_ID.startswith("CVE-"))
        self.assertEqual(len(first.Content_Hash), 64)
        self.assertTrue(len(first.Raw_Content) > 0)

    def test_portswigger_rss_collector(self):
        collector = create_portswigger_collector()
        items = collector.collect(limit=2)
        self.assertGreaterEqual(len(items), 1)
        first = items[0]
        self.assertEqual(first.Source_Type, SourceType.PORTSWIGGER)
        self.assertTrue(first.Source_URL.startswith("http"))
        self.assertTrue(len(first.Raw_Content) > 0)

    def test_github_advisory_collector(self):
        collector = GitHubAdvisoryCollector(ecosystems=["npm"])
        items = collector.collect(limit=2)
        self.assertGreaterEqual(len(items), 1)
        first = items[0]
        self.assertEqual(first.Source_Type, SourceType.GITHUB_ADVISORY)
        self.assertTrue(len(first.Content_Hash), 64)

    def test_frida_collector(self):
        from Backend.ingestion.collectors.mobile_sources import FridaCollector
        collector = FridaCollector()
        items = collector.collect(limit=2)
        self.assertGreaterEqual(len(items), 1)
        self.assertEqual(items[0].Source_Type, SourceType.FRIDA)
        self.assertIn("Frida", items[0].Vendor_Product)

    def test_nvd_collector(self):
        from Backend.ingestion.collectors.nvd import NvdCollector
        collector = NvdCollector()
        items = collector.collect(limit=1, query_by_date=False)
        self.assertGreaterEqual(len(items), 1)
        self.assertEqual(items[0].Source_Type, SourceType.NVD)
        self.assertTrue(items[0].CVE_ID.startswith("CVE-"))

    def test_github_poc_detector(self):
        from Backend.ingestion.collectors.github_poc import GitHubPoCDetector
        detector = GitHubPoCDetector()
        pocs = detector.find_pocs_for_cve("CVE-2024-0044", limit=2)
        # Verify it returns a list of PoCReference
        self.assertIsInstance(pocs, list)



@unittest.skipUnless(ONLINE, "live feeds not reachable (offline)")
class TestIngestionPipeline(unittest.TestCase):
    """Tests the orchestrator pipeline run and JSON export."""

    def test_pipeline_execution_and_storage(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            temp_staging = Path(tmp_dir)
            pipeline = IngestionPipeline(staging_dir=temp_staging)

            # Run with a subset of fast sources and limit=1 for speedy testing
            summary = pipeline.run(
                sources=["cisa_kev", "portswigger"],
                limit_per_source=1,
                save_output=True,
            )

            self.assertGreaterEqual(summary["total_collected"], 2)
            self.assertIsNotNone(summary["output_file"])
            output_path = Path(summary["output_file"])
            self.assertTrue(output_path.exists())

            # Verify saved JSON
            with open(output_path, "r", encoding="utf-8") as f:
                saved_data = json.load(f)
            self.assertIsInstance(saved_data, list)
            self.assertGreaterEqual(len(saved_data), 2)
            self.assertIn("Item_ID", saved_data[0])
            self.assertIn("Content_Hash", saved_data[0])
            self.assertIn("Raw_Content", saved_data[0])


if __name__ == "__main__":
    unittest.main()
