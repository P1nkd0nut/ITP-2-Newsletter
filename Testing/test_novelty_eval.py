"""
Tests for the novelty threshold tuning (Backend/run_novelty_eval.py) and for
how the digest picks up the tuned threshold. No Ollama needed.
"""
import json
import tempfile
import unittest
from pathlib import Path

from Backend import run_novelty_eval as ev
from Backend.api.novelty import DEFAULT_SIMILARITY, similarity_threshold


class FakeEmbedder:
    """Duplicates share a vector; distinct texts point elsewhere."""

    def embed_documents(self, texts):
        return [[1.0, 0.0] for _ in texts]

    def embed_query(self, text):
        return [1.0, 0.1] if text.startswith("dup") else [0.2, 1.0]


class TestThresholdChoice(unittest.TestCase):
    def test_separable_scores_give_a_threshold_between_them(self):
        scored = [(0.97, True), (0.95, True), (0.88, False), (0.80, False)]
        t = ev.choose_threshold(scored)
        self.assertTrue(0.88 < t < 0.95)
        self.assertEqual(ev.rates(scored, t), {"suppression_rate": 1.0, "false_suppression_rate": 0.0, "accuracy": 1.0})

    def test_ties_prefer_the_higher_threshold(self):
        # 0.90 is both a duplicate and a distinct pair: either way one is wrong, so keep new items
        scored = [(0.95, True), (0.90, True), (0.90, False), (0.80, False)]
        self.assertGreater(ev.choose_threshold(scored), 0.90)

    def test_cosine(self):
        self.assertAlmostEqual(ev.cosine([1, 0], [1, 0]), 1.0)
        self.assertAlmostEqual(ev.cosine([1, 0], [0, 1]), 0.0)
        self.assertEqual(ev.cosine([0, 0], [1, 0]), 0.0)

    def test_evaluate_reports_heldout_rates(self):
        pairs = [
            {"id": "1", "split": "tune", "label": "DUPLICATE", "a": "x", "b": "dup 1"},
            {"id": "2", "split": "tune", "label": "DISTINCT", "a": "x", "b": "other"},
            {"id": "3", "split": "heldout", "label": "DUPLICATE", "a": "x", "b": "dup 2"},
            {"id": "4", "split": "heldout", "label": "DISTINCT", "a": "x", "b": "other 2"},
        ]
        result = ev.evaluate(ev.score_pairs(pairs, FakeEmbedder()))
        self.assertEqual(result["heldout"]["suppression_rate"], 1.0)
        self.assertEqual(result["heldout"]["false_suppression_rate"], 0.0)


class TestLabelledPairs(unittest.TestCase):
    def test_dataset_is_balanced_and_split(self):
        pairs = json.loads(ev.PAIRS_FILE.read_text(encoding="utf-8"))["pairs"]
        self.assertEqual(len({p["id"] for p in pairs}), len(pairs))
        for split in ("tune", "heldout"):
            labels = [p["label"] for p in pairs if p["split"] == split]
            self.assertEqual(labels.count("DUPLICATE"), labels.count("DISTINCT"))
            self.assertGreaterEqual(len(labels), 10)


class TestDigestUsesTunedThreshold(unittest.TestCase):
    def test_env_wins_then_tuned_file_then_default(self):
        with tempfile.TemporaryDirectory() as d:
            tuned = Path(d) / "novelty_threshold.json"
            self.assertEqual(similarity_threshold("", tuned), DEFAULT_SIMILARITY)
            tuned.write_text(json.dumps({"threshold": 0.87}), encoding="utf-8")
            self.assertEqual(similarity_threshold(None, tuned), 0.87)
            self.assertEqual(similarity_threshold("0.95", tuned), 0.95)


if __name__ == "__main__":
    unittest.main()
