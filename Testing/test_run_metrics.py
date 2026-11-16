"""
Tests for per-stage latency and LLM cost reporting (plan Task 4.1).
"""
import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

from Backend import llm_usage, run_pipeline


class TestLlmUsage(unittest.TestCase):
    def test_records_tokens_and_cost_and_totals_by_stage(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "usage.jsonl"
            body = {"usage": {"prompt_tokens": 100, "completion_tokens": 20, "cost": 0.0004}}
            llm_usage.record("triage", "qwen", body, path)
            llm_usage.record("triage", "qwen", body, path)
            llm_usage.record("summaries", "qwen", {"usage": {"prompt_tokens": 900, "completion_tokens": 200}}, path)
            t = llm_usage.totals(path=path)
            self.assertEqual(t["triage"]["calls"], 2)
            self.assertAlmostEqual(t["triage"]["cost_usd"], 0.0008)
            self.assertEqual(t["summaries"]["prompt_tokens"], 900)

    def test_totals_only_count_this_run(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "usage.jsonl"
            llm_usage.record("triage", "qwen", {"usage": {"cost": 1.0}}, path)
            llm_usage.record("triage", "qwen", {"choices": []}, path)  # no usage block: not logged
            self.assertEqual(len(path.read_text(encoding="utf-8").splitlines()), 1)
            later = datetime.now(timezone.utc) + timedelta(seconds=1)
            self.assertEqual(llm_usage.totals(since=later, path=path), {})

    def test_bad_response_never_raises(self):
        llm_usage.record("triage", "qwen", None, Path("/nonexistent/dir/usage.jsonl"))


class TestRunReport(unittest.TestCase):
    def test_report_has_stage_times_and_cost(self):
        with tempfile.TemporaryDirectory() as d:
            started = datetime.now(timezone.utc)
            run_pipeline.STAGE_TIMES[:] = [{"stage": "Triage", "seconds": 12.5, "ok": True}]
            with mock.patch.object(llm_usage, "totals", return_value={
                    "triage": {"calls": 3, "prompt_tokens": 10, "completion_tokens": 5, "cost_usd": 0.002}}):
                metrics = run_pipeline.report_run(started, started + timedelta(seconds=30), Path(d) / "m.jsonl")
            self.assertEqual(metrics["total_seconds"], 30.0)
            self.assertEqual(metrics["llm_cost_usd"], 0.002)
            saved = json.loads((Path(d) / "m.jsonl").read_text(encoding="utf-8"))
            self.assertEqual(saved["stages"][0]["stage"], "Triage")
            run_pipeline.STAGE_TIMES.clear()


if __name__ == "__main__":
    unittest.main()
