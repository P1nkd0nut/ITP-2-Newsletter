"""
Unit and integration tests for the GroundedCVE ground-truth benchmark.
"""
import unittest
from Backend.run_benchmark import (
    load_ground_truth_dataset,
    convert_gt_to_envelope,
    audit_fact_extraction,
)
from Backend.triage.models import ScopeCategory
from Backend.triage.pre_filter import PentestPreFilter
from Backend.triage.priority_scorer import PriorityScoringEngine


class TestGroundTruthBenchmark(unittest.TestCase):
    """Verifies the 20-Sample Ground-Truth Validation Dataset and Evaluators."""

    def setUp(self):
        self.dataset = load_ground_truth_dataset()
        self.pre_filter = PentestPreFilter()

    def test_ground_truth_count_and_balance(self):
        """Verifies exactly 20 items: 10 Web and 10 Mobile."""
        self.assertEqual(len(self.dataset), 20)
        web_items = [x for x in self.dataset if x["platform"] == "WEB"]
        mobile_items = [x for x in self.dataset if x["platform"] == "MOBILE"]
        self.assertEqual(len(web_items), 10)
        self.assertEqual(len(mobile_items), 10)

    def test_required_ground_truth_fields(self):
        """Verifies all required audit fields exist for every benchmark disclosure."""
        required_fields = [
            "id", "cve_id", "title", "platform", "vendor_product",
            "affected_versions", "cvss", "kev_status", "has_public_poc",
            "official_url", "raw_content", "expected_ai_severity",
            "expected_cvss_discrepancy"
        ]
        for item in self.dataset:
            for field in required_fields:
                self.assertIn(field, item, f"Missing {field} in {item.get('id')}")
            self.assertTrue(item["cve_id"].startswith("CVE-"))
            self.assertTrue(item["official_url"].startswith("http"))
            self.assertGreater(len(item["raw_content"]), 40)

    def test_envelope_conversion_integrity(self):
        """Verifies conversion to StagingEnvelope maintains cryptographic hash & raw data."""
        item = self.dataset[0]
        env = convert_gt_to_envelope(item)
        self.assertEqual(env.CVE_ID, item["cve_id"])
        self.assertEqual(env.Raw_Content, item["raw_content"])
        self.assertEqual(len(env.Content_Hash), 64)
        self.assertTrue(env.Content_Hash.isalnum())

    def test_scope_pre_filter_accuracy_on_benchmark(self):
        """Verifies that all 20 disclosures are 100% correctly isolated into WEB or MOBILE."""
        correct = 0
        for item in self.dataset:
            env = convert_gt_to_envelope(item)
            decision = self.pre_filter.evaluate(env)
            self.assertTrue(decision.is_in_scope)
            expected_scope = ScopeCategory[item["platform"]]
            if decision.category == expected_scope:
                correct += 1
        accuracy = (correct / len(self.dataset)) * 100.0
        self.assertEqual(accuracy, 100.0, f"Expected 100% scope accuracy, got {accuracy}%")

    def test_fact_extraction_precision_benchmark(self):
        """Verifies FEP >= 95% on the curated ground-truth disclosures."""
        total_checks = 0
        passed_checks = 0
        for item in self.dataset:
            env = convert_gt_to_envelope(item)
            audit = audit_fact_extraction(env, item)
            for _, passed in audit.items():
                total_checks += 1
                if passed:
                    passed_checks += 1
        fep = (passed_checks / total_checks) * 100.0
        self.assertGreaterEqual(fep, 95.0, f"FEP fell below 95%: {fep}%")

    def test_known_anomaly_detection(self):
        """Verifies that the CVSS discrepancy gate correctly triggers on CVE-2026-94138."""
        anomaly_item = next(x for x in self.dataset if x["cve_id"] == "CVE-2026-94138")
        env = convert_gt_to_envelope(anomaly_item)
        engine = PriorityScoringEngine(kev_catalog=set())
        record = engine.process_envelope(env)

        self.assertIsNotNone(record.discrepancy)
        self.assertTrue(record.discrepancy.is_discrepancy)
        self.assertGreaterEqual(record.discrepancy.delta, 4.0)


class TestSeverityAgreement(unittest.TestCase):
    def test_mean_absolute_error_and_within_one(self):
        from Backend.run_benchmark import severity_agreement
        result = severity_agreement([(9.5, 9.8), (7.0, 9.0), (3.5, 3.5), (6.0, None)])
        self.assertEqual(result["n"], 3)
        self.assertAlmostEqual(result["mae"], round((0.3 + 2.0 + 0.0) / 3, 2))
        self.assertAlmostEqual(result["within_1_pct"], 66.7)

    def test_no_labels(self):
        from Backend.run_benchmark import severity_agreement
        self.assertIsNone(severity_agreement([(5.0, None)])["mae"])


if __name__ == "__main__":
    unittest.main()
