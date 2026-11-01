"""
Offline tests for the digest novelty check: one item per CVE, and no repeats
across weekly digests unless something new happened.

Run:
    python -m pytest Testing/test_novelty.py -v
"""
import hashlib
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from qdrant_client import QdrantClient

from Backend.api import telegram_service as tg
from Backend.api.novelty import NoveltyChecker, PublishedIndex, merge_same_flaw
from Backend.config import EMBED_DIM


def item(item_id, score=50.0, cve=None, source="NVD", kev=False, pocs=0, cvss=None, text=None):
    return {
        "envelope": {
            "Item_ID": item_id, "CVE_ID": cve, "Source_Type": source, "Title": f"Title {item_id}",
            "Published_Date": (datetime.now(timezone.utc) - timedelta(days=1)).isoformat(),
            "KEV_Status": kev, "PoC_URLs": [f"https://github.com/x/poc{i}" for i in range(pocs)], "CVSS": cvss,
        },
        "pre_filter": {"category": "WEB", "is_in_scope": True},
        "priority_score": score,
        "grounded_card": {"mechanism": text or f"Mechanism of {item_id}.", "impact": "Impact."},
    }


class FakeEmbedder:
    @staticmethod
    def _vec(text):
        v = [0.0] * EMBED_DIM
        for word in text.lower().split():
            v[int(hashlib.md5(word.encode()).hexdigest(), 16) % EMBED_DIM] += 1.0
        return v

    def embed_documents(self, texts):
        return [self._vec(t) for t in texts]

    def embed_query(self, text):
        return self._vec(text)


class TestMergeSameFlaw(unittest.TestCase):
    def test_one_item_per_cve_keeping_the_first(self):
        merged = merge_same_flaw([
            item("cisa-kev-cve-1", 90, cve="CVE-2026-1", source="CISA_KEV"),
            item("nvd-cve-1", 50, cve="cve-2026-1", source="NVD"),
            item("ghsa-1", 40, cve="CVE-2026-1", source="GITHUB_ADVISORY"),
            item("writeup", 30),
        ])
        self.assertEqual([c["envelope"]["Item_ID"] for c in merged], ["cisa-kev-cve-1", "writeup"])
        self.assertEqual(merged[0]["also_reported_by"], ["NVD", "GITHUB_ADVISORY"])


class TestNoveltyChecker(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.ledger = Path(self.tmp.name) / "ledger.json"

    def tearDown(self):
        self.tmp.cleanup()

    def test_sent_item_is_skipped_until_something_new_happens(self):
        checker = NoveltyChecker(self.ledger)
        c = item("a", cve="CVE-2026-1", cvss=7.5)
        self.assertEqual(checker.assess(c)["status"], "NEW")
        checker.record([c])

        checker = NoveltyChecker(self.ledger)  # ledger survives between runs
        self.assertEqual(checker.assess(c)["status"], "SEEN")
        self.assertEqual(checker.filter([c]), [])

        updated = item("a", cve="CVE-2026-1", cvss=7.5, kev=True, pocs=1)
        verdict = checker.assess(updated)
        self.assertEqual(verdict["status"], "UPDATE")
        self.assertEqual(verdict["reasons"], ["now actively exploited (CISA KEV)", "new public PoC"])

    def test_same_cve_from_another_source_counts_as_sent(self):
        checker = NoveltyChecker(self.ledger)
        checker.record([item("nvd-cve-1", cve="CVE-2026-1")])
        self.assertEqual(checker.assess(item("ghsa-1", cve="CVE-2026-1", source="GITHUB_ADVISORY"))["status"], "SEEN")

    def test_cvss_change_is_an_update(self):
        checker = NoveltyChecker(self.ledger)
        checker.record([item("a", cve="CVE-2026-1")])
        self.assertEqual(checker.assess(item("a", cve="CVE-2026-1", cvss=9.8))["reasons"], ["CVSS now 9.8"])


class TestPublishedIndex(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        index = PublishedIndex(QdrantClient(":memory:"), FakeEmbedder(), collection="test_published")
        self.checker = NoveltyChecker(Path(self.tmp.name) / "ledger.json", index=index)
        text = "Request smuggling in a popular reverse proxy lets attackers poison caches."
        self.checker.record([item("portswigger-1", text=text)])
        self.text = text

    def tearDown(self):
        self.tmp.cleanup()

    def test_near_identical_writeup_is_a_duplicate(self):
        verdict = self.checker.assess(item("project-zero-9", text=self.text))
        self.assertEqual(verdict["status"], "DUPLICATE")
        self.assertEqual(verdict["duplicate_of"], "portswigger-1")

    def test_different_writeup_is_new(self):
        other = item("project-zero-9", text="Kernel use-after-free in a GPU driver allows privilege escalation.")
        self.assertEqual(self.checker.assess(other)["status"], "NEW")

    def test_items_with_a_cve_are_matched_by_cve_not_by_text(self):
        same_text_new_cve = item("nvd-cve-2", cve="CVE-2026-2", text=self.text)
        self.assertEqual(self.checker.assess(same_text_new_cve)["status"], "NEW")


class TestDigestUsesNovelty(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.checker = NoveltyChecker(Path(self.tmp.name) / "ledger.json")

    def tearDown(self):
        self.tmp.cleanup()

    def test_already_sent_items_free_up_slots_for_new_ones(self):
        sent = item("sent", 99, cve="CVE-2026-9")
        self.checker.record([sent])
        candidates = [sent, item("b", 80), item("c", 70), item("d", 60)]
        picked = tg.select_digest_items(candidates, days=7, top_n=2, novelty=self.checker)
        self.assertEqual([c["envelope"]["Item_ID"] for c in picked], ["b", "c"])

    def test_update_is_sent_again_with_what_changed(self):
        self.checker.record([item("a", cve="CVE-2026-1")])
        picked = tg.select_digest_items([item("a", cve="CVE-2026-1", kev=True)], novelty=self.checker)
        msg = tg.format_digest_item(picked[0], 1)
        self.assertIn("🔁 Update: now actively exploited (CISA KEV)", msg)

    def test_digest_sends_each_cve_once(self):
        candidates = [item("kev", 90, cve="CVE-2026-1", source="CISA_KEV"), item("nvd", 50, cve="CVE-2026-1")]
        messages = tg.build_weekly_digest(candidates, days=7)
        self.assertEqual(len(messages), 2)  # header + one incident


if __name__ == "__main__":
    unittest.main()
