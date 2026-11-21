"""
Offline tests for chunk indexing, grounded card writing and the publish gate.

Qdrant runs in-process (QdrantClient(":memory:")), and Ollama / OpenRouter are
replaced with fakes, so nothing here touches the network.

Run:
    python -m pytest Testing/test_grounded_summaries.py -v
"""
import hashlib
import json
import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from qdrant_client import QdrantClient

from Backend.api import data_service as ds
from Backend.api import telegram_service as tg
from Backend.chunking.models import Chunk
from Backend.config import EMBED_DIM
from Backend.ingestion.models import SourceType, StagingEnvelope
from Backend import run_pipeline
from Backend.run_summarise import select_items
from Backend.storage import embedder as embedder_mod
from Backend.storage.embedder import OllamaEmbedder
from Backend.storage.indexer import ChunkRetriever, index_chunks
from Backend.summarisation import GroundedSummariser, build_prompt, load_cards, log_rejected, parse_card, save_cards

COLLECTION = "test_items"

SUMMARY = (
    "CVE-2023-4966: Sensitive information disclosure in NetScaler ADC and NetScaler Gateway "
    "versions 13.1 before 13.1-49.15. Unauthenticated remote attackers can extract session "
    "tokens from uninitialized memory via a buffer over-read, bypassing multi-factor authentication."
)
POC = 'curl -k -s -H "Host: aaaa" https://target-gateway.com/oauth/idp/.well-known/openid-configuration'
OTHER_ITEM_TEXT = "CVE-2099-0001: An unrelated flaw in another product leading to remote code execution."


def make_envelope(item_id="citrix", raw=SUMMARY + "\n" + POC) -> StagingEnvelope:
    return StagingEnvelope(
        Item_ID=item_id,
        Source_Type=SourceType.NVD,
        Title="Citrix Bleed",
        Source_URL="https://nvd.nist.gov/vuln/detail/CVE-2023-4966",
        Published_Date=datetime.now(timezone.utc).isoformat(),
        Ingested_At=datetime.now(timezone.utc).isoformat(),
        Content_Hash=hashlib.sha256(raw.encode()).hexdigest(),
        Raw_Content=raw,
        CVE_ID="CVE-2023-4966",
        CVSS=9.4,
    )


def make_chunk(item_id, text, tier=1, index=0) -> dict:
    return Chunk(
        Chunk_ID=f"{item_id}::t{tier}::{index:03d}", Item_ID=item_id, Tier=tier, Chunk_Index=index,
        Text=text, Source_Type="NVD", Source_URL="https://example.com", Title=item_id,
    ).to_dict()


CHUNKS = [
    make_chunk("citrix", SUMMARY, tier=1),
    make_chunk("citrix", "Proof of concept:\n" + POC, tier=2),
    make_chunk("other", OTHER_ITEM_TEXT, tier=1),
]


class FakeEmbedder:
    """Deterministic 768-dim vectors; words shared between texts make them closer."""

    def __init__(self):
        self.document_calls = 0

    @staticmethod
    def _vec(text):
        v = [0.0] * EMBED_DIM
        for word in text.lower().split():
            v[int(hashlib.md5(word.encode()).hexdigest(), 16) % EMBED_DIM] += 1.0
        v[0] += 0.01  # never all zeros
        return v

    def embed_documents(self, texts):
        self.document_calls += len(texts)
        return [self._vec(t) for t in texts]

    def embed_query(self, text):
        return self._vec(text)


def honest_card_json(**changes) -> str:
    card = dict(
        mechanism="CVE-2023-4966 is a buffer over-read in NetScaler ADC and NetScaler Gateway.",
        impact="Unauthenticated remote attackers can extract session tokens, bypassing multi-factor "
               "authentication. Affects 13.1 before 13.1-49.15.",
        testing_syntax=[POC],
        remediation="Upgrade to a fixed build.",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2023-4966"],
    )
    card.update(changes)
    return json.dumps(card)


HALLUCINATED = honest_card_json(impact="Leads to remote code execution in 13.1-99.99.")


class ScriptedLLM:
    """Returns the given responses in order and records every prompt it was sent."""

    def __init__(self, *responses):
        self.responses = list(responses)
        self.prompts = []
        self.model_name = "fake/llm"

    def __call__(self, system, user):
        self.prompts.append(user)
        r = self.responses.pop(0)
        if isinstance(r, Exception):
            raise r
        return r


# ---------------------------------------------------------------------------
# Embedding + Qdrant
# ---------------------------------------------------------------------------

class TestOllamaEmbedder(unittest.TestCase):
    def _fake_post(self, dim=EMBED_DIM):
        calls = []

        def post(url, json, timeout):
            calls.append(json)
            resp = mock.Mock()
            resp.raise_for_status = mock.Mock()
            resp.json.return_value = {"embeddings": [[0.1] * dim for _ in json["input"]]}
            return resp
        return post, calls

    def test_adds_nomic_task_prefixes_and_batches(self):
        post, calls = self._fake_post()
        with mock.patch.object(embedder_mod.requests, "post", side_effect=post):
            e = OllamaEmbedder(host="http://ollama:11434", batch_size=2)
            vecs = e.embed_documents(["a", "b", "c"])
            q = e.embed_query("find me")
        self.assertEqual(len(vecs), 3)
        self.assertEqual(len(q), EMBED_DIM)
        self.assertEqual([len(c["input"]) for c in calls], [2, 1, 1])
        self.assertEqual(calls[0]["input"][0], "search_document: a")
        self.assertEqual(calls[-1]["input"][0], "search_query: find me")
        self.assertEqual(calls[0]["model"], "nomic-embed-text")

    def test_wrong_vector_size_is_an_error(self):
        post, _ = self._fake_post(dim=384)
        with mock.patch.object(embedder_mod.requests, "post", side_effect=post):
            with self.assertRaises(RuntimeError):
                OllamaEmbedder().embed_documents(["a"])


class TestQdrantIndexing(unittest.TestCase):
    def setUp(self):
        self.client = QdrantClient(":memory:")
        self.embedder = FakeEmbedder()

    def test_upserts_every_chunk_with_payload(self):
        stats = index_chunks(CHUNKS, self.client, self.embedder, collection=COLLECTION)
        self.assertEqual(stats, {"total": 3, "embedded": 3, "skipped": 0})
        self.assertEqual(self.client.count(COLLECTION).count, 3)
        point = self.client.retrieve(COLLECTION, ids=[CHUNKS[0]["Point_ID"]], with_payload=True)[0]
        self.assertEqual(point.payload["Item_ID"], "citrix")
        self.assertEqual(point.payload["Text"], SUMMARY)

    def test_rerun_skips_unchanged_chunks(self):
        index_chunks(CHUNKS, self.client, self.embedder, collection=COLLECTION)
        changed = [dict(CHUNKS[0], Text=SUMMARY + " Updated.", Chunk_Hash="new")] + CHUNKS[1:]
        stats = index_chunks(changed, self.client, self.embedder, collection=COLLECTION)
        self.assertEqual(stats["embedded"], 1)
        self.assertEqual(stats["skipped"], 2)

    def test_removes_chunks_an_item_no_longer_has(self):
        index_chunks(CHUNKS, self.client, self.embedder, collection=COLLECTION)
        index_chunks([CHUNKS[0], CHUNKS[2]], self.client, self.embedder, collection=COLLECTION)
        self.assertEqual(self.client.count(COLLECTION).count, 2)

    def test_retrieval_returns_only_the_items_own_chunks(self):
        index_chunks(CHUNKS, self.client, self.embedder, collection=COLLECTION)
        retriever = ChunkRetriever(self.client, self.embedder, collection=COLLECTION)
        chunks, mode = retriever.retrieve("citrix", "remote code execution in another product")
        self.assertEqual(mode, "qdrant")
        self.assertEqual({c["Item_ID"] for c in chunks}, {"citrix"})
        self.assertEqual([c["Tier"] for c in chunks], [1, 2])  # document order

    def test_falls_back_to_chunks_file_when_qdrant_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "chunks.json"
            path.write_text(json.dumps(CHUNKS), encoding="utf-8")
            broken = mock.Mock()
            broken.query_points.side_effect = ConnectionError("down")
            chunks, mode = ChunkRetriever(broken, self.embedder, chunks_file=path).retrieve("citrix", "q")
        self.assertEqual(mode, "file")
        self.assertEqual(len(chunks), 2)


# ---------------------------------------------------------------------------
# Grounded summariser + gate
# ---------------------------------------------------------------------------

class StaticRetriever:
    def __init__(self, chunks):
        self.chunks = chunks

    def retrieve(self, item_id, query, limit=8):
        return [c for c in self.chunks if c["Item_ID"] == item_id][:limit], "file"


class TestGroundedSummariser(unittest.TestCase):
    def setUp(self):
        self.env = make_envelope()
        self.retriever = StaticRetriever(CHUNKS)

    def test_prompt_contains_only_the_items_own_chunks(self):
        prompt = build_prompt(self.env, self.retriever.retrieve("citrix", "")[0])
        self.assertIn(SUMMARY, prompt)
        self.assertIn(POC, prompt)
        self.assertNotIn("CVE-2099-0001", prompt)

    def test_parse_card_accepts_code_fences(self):
        card = parse_card("```json\n" + honest_card_json(testing_syntax=POC) + "\n```")
        self.assertEqual(card.testing_syntax, [POC])

    def test_honest_card_passes_first_time(self):
        llm = ScriptedLLM(honest_card_json())
        rec = GroundedSummariser(llm, self.retriever).summarise(self.env)
        self.assertEqual(rec["status"], "PASSED")
        self.assertEqual(rec["verification"]["attempts"], 1)
        self.assertEqual(rec["chunk_ids"], ["citrix::t1::000", "citrix::t2::000"])
        self.assertEqual(len(llm.prompts), 1)

    def test_failed_draft_is_regenerated_once_with_the_reasons(self):
        llm = ScriptedLLM(HALLUCINATED, honest_card_json())
        rec = GroundedSummariser(llm, self.retriever).summarise(self.env)
        self.assertEqual(rec["status"], "PASSED")
        self.assertEqual(rec["verification"]["attempts"], 2)
        self.assertIn("13.1-99.99", llm.prompts[1])
        self.assertIn("remote code execution", llm.prompts[1])

    def test_card_that_fails_twice_is_quarantined(self):
        llm = ScriptedLLM(HALLUCINATED, HALLUCINATED)
        rec = GroundedSummariser(llm, self.retriever).summarise(self.env)
        self.assertEqual(rec["status"], "QUARANTINED")
        checks = {f["check"] for f in rec["verification"]["failures"]}
        self.assertEqual(checks, {"IMPACT", "VERSION"})

    def test_fact_from_another_items_chunk_is_caught(self):
        llm = ScriptedLLM(*[honest_card_json(mechanism="Related to CVE-2099-0001.")] * 2)
        rec = GroundedSummariser(llm, self.retriever).summarise(self.env)
        self.assertEqual(rec["status"], "QUARANTINED")

    def test_no_chunks_or_llm_failure_is_an_error_not_a_card(self):
        rec = GroundedSummariser(ScriptedLLM(), StaticRetriever([])).summarise(self.env)
        self.assertEqual(rec["status"], "ERROR")
        rec = GroundedSummariser(ScriptedLLM(RuntimeError("503")), self.retriever).summarise(self.env)
        self.assertEqual(rec["status"], "ERROR")
        self.assertIsNone(rec["card"])


    def test_kev_card_can_use_the_attached_nvd_record(self):
        # The KEV entry names no version; the NVD record attached at ingestion does
        kev = make_envelope()
        kev.Raw_Content = "CVE-2023-4966 NetScaler buffer over-read. Apply updates per vendor instructions."
        kev_chunks = StaticRetriever([make_chunk("citrix", kev.Raw_Content)])
        card = honest_card_json(impact="Affects NetScaler ADC 14.1 before 14.1-8.50.", testing_syntax=[])
        rec = GroundedSummariser(ScriptedLLM(card, card), kev_chunks).summarise(kev)
        self.assertEqual(rec["status"], "QUARANTINED")  # nothing names 14.1-8.50

        kev.Extra_Metadata = {"nvd_record": "NVD record for CVE-2023-4966\n"
                                            "Affected versions: Citrix Netscaler Application Delivery Controller from 14.1 before 14.1-8.50"}
        llm = ScriptedLLM(card)
        rec = GroundedSummariser(llm, kev_chunks).summarise(kev)
        self.assertEqual(rec["status"], "PASSED", rec["verification"])
        self.assertIn("NVD record", llm.prompts[0])
        self.assertIsNotNone(rec["nvd_record_hash"])

class TestCardStore(unittest.TestCase):
    def test_only_passed_cards_are_saved_and_rejects_are_logged(self):
        passed = {"Item_ID": "a", "status": "PASSED", "card": {"mechanism": "m"}}
        quarantined = {"Item_ID": "b", "status": "QUARANTINED", "card": {"mechanism": "bad"}}
        with tempfile.TemporaryDirectory() as tmp:
            cards_path, log_path = Path(tmp) / "cards.json", Path(tmp) / "q.jsonl"
            save_cards({"a": passed, "b": quarantined}, cards_path)
            self.assertEqual(list(load_cards(cards_path)), ["a"])
            log_rejected([quarantined], log_path)
            log_rejected([quarantined], log_path)
            lines = log_path.read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(lines), 2)
        self.assertEqual(json.loads(lines[0])["status"], "QUARANTINED")


class TestSelectItems(unittest.TestCase):
    def test_picks_recent_in_scope_items_by_priority(self):
        now = datetime.now(timezone.utc)
        def cand(i, score, in_scope=True, age=1):
            return {"envelope": {"Item_ID": i, "Published_Date": (now - timedelta(days=age)).isoformat()},
                    "pre_filter": {"is_in_scope": in_scope}, "priority_score": score}
        items = [cand("a", 10), cand("b", 90), cand("c", 99, in_scope=False), cand("d", 95, age=30)]
        self.assertEqual([c["envelope"]["Item_ID"] for c in select_items(items, 5, 7)], ["b", "a"])
        self.assertEqual([c["envelope"]["Item_ID"] for c in select_items(items, 5, 0)], ["d", "b", "a"])


# ---------------------------------------------------------------------------
# Only passed cards reach the dashboard digest and Telegram
# ---------------------------------------------------------------------------

class TestPublishingUsesOnlyVerifiedCards(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        tmp = Path(self.tmp.name)
        verified, unverified, stale = (make_envelope(i, raw=SUMMARY + i) for i in ("verified", "unverified", "stale"))
        candidates = [
            {"envelope": e.model_dump(mode="json"), "priority_score": s, "triaged_at": "",
             "pre_filter": {"category": "WEB", "is_in_scope": True, "reason": ""}}
            for e, s in ((verified, 50.0), (unverified, 90.0), (stale, 80.0))
        ]
        (tmp / "triaged.json").write_text(json.dumps(candidates), encoding="utf-8")
        card = json.loads(honest_card_json(mechanism="Grounded write-up."))
        records = [
            {"Item_ID": "verified", "status": "PASSED", "Content_Hash": verified.Content_Hash, "card": card,
             "verification": {"checks_run": 4, "attempts": 1}},
            # card written before the source changed
            {"Item_ID": "stale", "status": "PASSED", "Content_Hash": "old-hash", "card": card},
        ]
        (tmp / "cards.json").write_text(json.dumps(records), encoding="utf-8")
        self.patches = [
            mock.patch.object(ds, "TRIAGED_FILE", tmp / "triaged.json"),
            mock.patch.object(ds, "GROUNDED_CARDS_FILE", tmp / "cards.json"),
            mock.patch.object(ds.link_validator, "check_single_link",
                              side_effect=lambda url, **kw: {"url": url, "status": "unchecked"}),
        ]
        for p in self.patches:
            p.start()
        self.service = ds.DataService()

    def tearDown(self):
        for p in self.patches:
            p.stop()
        self.tmp.cleanup()

    def test_card_attached_only_when_it_matches_the_current_source(self):
        by_id = {c["envelope"]["Item_ID"]: c for c in self.service.get_all_candidates()}
        self.assertEqual(by_id["verified"]["grounded_card"]["mechanism"], "Grounded write-up.")
        self.assertEqual(by_id["verified"]["in_depth"]["brief_summary"], "Grounded write-up.")
        self.assertIsNone(by_id["unverified"]["grounded_card"])
        self.assertIsNone(by_id["stale"]["grounded_card"])

    def test_dashboard_digest_contains_only_verified_items(self):
        digest = self.service.generate_newsletter_digest(top_n=5)
        self.assertEqual([t["cve_id"] for t in digest["curated_threats"]], ["CVE-2023-4966"])
        self.assertEqual(digest["verified_count"], 1)
        self.assertIn("Grounded write-up.", digest["markdown"])

    def test_telegram_digest_contains_only_verified_items(self):
        messages = tg.build_weekly_digest(self.service.get_all_candidates(), days=7, top_n=10)
        self.assertEqual(len(messages), 2)
        self.assertNotIn("/incident/", "".join(messages))  # no dashboard links in Telegram
        self.assertIn("Grounded write-up.", messages[1])

    def test_dashboard_picks_up_new_cards_without_a_restart(self):
        self.assertIsNone({c["envelope"]["Item_ID"]: c for c in self.service.get_all_candidates()}["unverified"]["grounded_card"])
        cards_path = ds.GROUNDED_CARDS_FILE
        records = json.loads(cards_path.read_text(encoding="utf-8"))
        unverified_hash = next(c["envelope"]["Content_Hash"] for c in self.service.get_all_candidates()
                               if c["envelope"]["Item_ID"] == "unverified")
        records.append(dict(records[0], Item_ID="unverified", Content_Hash=unverified_hash))
        cards_path.write_text(json.dumps(records), encoding="utf-8")
        os.utime(cards_path, ns=(1, 1))  # make sure the mtime differs on coarse filesystems
        by_id = {c["envelope"]["Item_ID"]: c for c in self.service.get_all_candidates()}
        self.assertIsNotNone(by_id["unverified"]["grounded_card"])


class TestPipelineDigestSchedule(unittest.TestCase):
    def test_digest_due_after_interval_only(self):
        now = datetime(2026, 11, 8, tzinfo=timezone.utc)
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "last.json"
            self.assertTrue(run_pipeline.digest_due(now, 7, state))  # never sent
            state.write_text(json.dumps({"sent_at": (now - timedelta(days=3)).isoformat()}), encoding="utf-8")
            self.assertFalse(run_pipeline.digest_due(now, 7, state))
            state.write_text(json.dumps({"sent_at": (now - timedelta(days=7)).isoformat()}), encoding="utf-8")
            self.assertTrue(run_pipeline.digest_due(now, 7, state))

    def test_next_run_is_8am_singapore_time(self):
        sg = "Asia/Singapore"
        before = datetime(2026, 11, 1, 23, 0, tzinfo=timezone.utc)   # 07:00 SGT on 2 Nov
        after = datetime(2026, 11, 2, 1, 0, tzinfo=timezone.utc)     # 09:00 SGT on 2 Nov
        self.assertEqual(run_pipeline.next_run_at(before, "08:00", sg),
                         datetime(2026, 11, 2, 0, 0, tzinfo=timezone.utc))
        self.assertEqual(run_pipeline.next_run_at(after, "08:00", sg),
                         datetime(2026, 11, 3, 0, 0, tzinfo=timezone.utc))


if __name__ == "__main__":
    unittest.main()
