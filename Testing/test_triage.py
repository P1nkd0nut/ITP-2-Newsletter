"""
Unit and Integration Tests for GroundedCVE Pentest Pre-Filter & AI Scoring Architecture.
Tests the Scope Pre-Filter Gate, AI Practical Severity Assessor,
100-Point Scoring Engine, and CVSS Discrepancy Anomaly Check.
"""
import unittest
from Backend.ingestion.models import StagingEnvelope, SourceType
from Backend.triage.models import ScopeCategory
from Backend.triage.pre_filter import PentestPreFilter
from Backend.triage.ai_evaluator import AISeverityEvaluator
from Backend.triage.priority_scorer import PriorityScoringEngine


class TestPentestPreFilter(unittest.TestCase):
    """Tests the dedicated Web and Mobile Scope Pre-Filter Gate."""

    def setUp(self):
        self.filter = PentestPreFilter()

    def test_source_origin_web(self):
        env = StagingEnvelope(
            Item_ID="test-ps-01",
            Source_Type=SourceType.PORTSWIGGER,
            Title="HTTP Request Smuggling Research",
            Source_URL="https://portswigger.net/research/test",
            Published_Date="2026-09-28T00:00:00Z",
            Ingested_At="2026-09-28T00:00:00Z",
            Content_Hash="abc",
            Raw_Content="Research details on HTTP desynchronization.",
        )
        decision = self.filter.evaluate(env)
        self.assertEqual(decision.category, ScopeCategory.WEB)
        self.assertTrue(decision.is_in_scope)
        self.assertEqual(decision.matched_by, "SOURCE_ORIGIN")

    def test_source_origin_mobile(self):
        env = StagingEnvelope(
            Item_ID="test-frida-01",
            Source_Type=SourceType.FRIDA,
            Title="Frida 17.19.0 Dynamic Instrumentation",
            Source_URL="https://github.com/frida/frida",
            Published_Date="2026-09-28T00:00:00Z",
            Ingested_At="2026-09-28T00:00:00Z",
            Content_Hash="abc",
            Raw_Content="Hooking updates for Android ART runtime.",
        )
        decision = self.filter.evaluate(env)
        self.assertEqual(decision.category, ScopeCategory.MOBILE)
        self.assertTrue(decision.is_in_scope)

    def test_cwe_taxonomy_web(self):
        env = StagingEnvelope(
            Item_ID="nvd-sqli-01",
            Source_Type=SourceType.NVD,
            Title="SQL Injection in Web Framework",
            Source_URL="https://nvd.nist.gov/vuln/detail/CVE-2026-1111",
            Published_Date="2026-09-28T00:00:00Z",
            Ingested_At="2026-09-28T00:00:00Z",
            Content_Hash="abc",
            Raw_Content="User input concatenated into SQL query.",
            CWE=["CWE-89"],
        )
        decision = self.filter.evaluate(env)
        self.assertEqual(decision.category, ScopeCategory.WEB)
        self.assertTrue(decision.is_in_scope)
        self.assertEqual(decision.matched_by, "CWE_TAXONOMY")

    def test_cwe_taxonomy_mobile(self):
        env = StagingEnvelope(
            Item_ID="nvd-ipc-01",
            Source_Type=SourceType.NVD,
            Title="Android Intent Hijacking in System App",
            Source_URL="https://nvd.nist.gov/vuln/detail/CVE-2026-2222",
            Published_Date="2026-09-28T00:00:00Z",
            Ingested_At="2026-09-28T00:00:00Z",
            Content_Hash="abc",
            Raw_Content="Broadcast receiver exported without permission checks.",
            CWE=["CWE-926"],
        )
        decision = self.filter.evaluate(env)
        self.assertEqual(decision.category, ScopeCategory.MOBILE)
        self.assertTrue(decision.is_in_scope)

    def test_out_of_scope_negative_filter(self):
        env = StagingEnvelope(
            Item_ID="nvd-printer-01",
            Source_Type=SourceType.NVD,
            Title="Denial of Service in Print Spooler Driver",
            Source_URL="https://nvd.nist.gov/vuln/detail/CVE-2026-3333",
            Published_Date="2026-09-28T00:00:00Z",
            Ingested_At="2026-09-28T00:00:00Z",
            Content_Hash="abc",
            Raw_Content="A flaw in the printer spooler driver causes buffer exhaustion.",
        )
        decision = self.filter.evaluate(env)
        self.assertEqual(decision.category, ScopeCategory.OUT_OF_SCOPE)
        self.assertFalse(decision.is_in_scope)
        self.assertEqual(decision.matched_by, "NEGATIVE_HEURISTIC")


class TestPriorityScorerAndAnomaly(unittest.TestCase):
    """Tests the 100-Point Scoring Engine and CVSS Anomaly Gate."""

    def setUp(self):
        self.kev_catalog = {"CVE-2026-88772", "CVE-2024-0044"}
        self.engine = PriorityScoringEngine(kev_catalog=self.kev_catalog)

    def test_100_point_scoring_breakdown(self):
        # High impact web flaw in KEV with public PoC
        env = StagingEnvelope(
            Item_ID="test-rce-01",
            Source_Type=SourceType.GITHUB_ADVISORY,
            Title="Critical RCE in Web API",
            Source_URL="https://example.com/advisory",
            Published_Date="2026-09-28T00:00:00Z",
            Ingested_At="2026-09-28T00:00:00Z",
            Content_Hash="abc",
            Raw_Content="Unauthenticated remote code execution in REST API endpoint.",
            CVE_ID="CVE-2026-88772",
            CVSS=9.8,
            PoC_URLs=["https://github.com/poc/test"],
        )
        candidate = self.engine.process_envelope(env)

        # In-scope check
        self.assertTrue(candidate.pre_filter.is_in_scope)
        self.assertEqual(candidate.pre_filter.category, ScopeCategory.WEB)

        # Score breakdown checks:
        # CISA KEV = 40.0 pts
        # AI Practical Severity >= 35.0 pts (for RCE)
        # PoC Availability = 20.0 pts
        # Total >= 95.0 / 100.0
        self.assertEqual(candidate.score_breakdown["cisa_kev_points"], 40.0)
        self.assertEqual(candidate.score_breakdown["poc_points"], 20.0)
        self.assertGreaterEqual(candidate.score_breakdown["ai_severity_points"], 35.0)
        self.assertGreaterEqual(candidate.priority_score, 95.0)
        self.assertLessEqual(candidate.priority_score, 100.0)

    def test_out_of_scope_receives_zero_score(self):
        env = StagingEnvelope(
            Item_ID="test-scada-01",
            Source_Type=SourceType.NVD,
            Title="Industrial Modbus PLC Communication Glitch",
            Source_URL="https://example.com/plc",
            Published_Date="2026-09-28T00:00:00Z",
            Ingested_At="2026-09-28T00:00:00Z",
            Content_Hash="abc",
            Raw_Content="A flaw in the SCADA PLC firmware controller.",
        )
        candidate = self.engine.process_envelope(env)
        self.assertFalse(candidate.pre_filter.is_in_scope)
        self.assertEqual(candidate.priority_score, 0.0)

    def test_cvss_discrepancy_anomaly_trigger(self):
        # Case: CVSS is 10.0, but flaw is a local Denial of Service (AI gives ~3.5)
        # Delta = |3.5 - 10.0| = 6.5 >= 4.0 threshold -> triggers discrepancy!
        env = StagingEnvelope(
            Item_ID="test-inflated-cve",
            Source_Type=SourceType.GITHUB_ADVISORY,
            Title="Local Resource Exhaustion Glitch",
            Source_URL="https://example.com/bug",
            Published_Date="2026-09-28T00:00:00Z",
            Ingested_At="2026-09-28T00:00:00Z",
            Content_Hash="abc",
            Raw_Content="A denial of service occurs causing a local memory leak under extreme load.",
            CVE_ID="CVE-2026-9999",
            CVSS=10.0,  # Vendor defaulted to worst-case 10.0
        )
        candidate = self.engine.process_envelope(env)
        self.assertIsNotNone(candidate.discrepancy)
        self.assertTrue(candidate.discrepancy.is_discrepancy)
        self.assertGreaterEqual(candidate.discrepancy.delta, 4.0)
        self.assertIn("significantly higher than AI severity", candidate.discrepancy.troubleshoot_note)


if __name__ == "__main__":
    unittest.main()
