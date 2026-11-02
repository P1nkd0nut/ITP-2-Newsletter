"""
Tests for hybrid search (Task 2.3 / 3.3): BM25 keyword ranking, RRF fusion,
per-item results, keyword-only fallback and the /api/search endpoint.

Qdrant runs in-process (QdrantClient(":memory:")) and the embedder is a
deterministic fake, so no Docker, Ollama or network is needed.

Run:
    python -m unittest Testing.test_search -v
"""
import hashlib
import json
import sys
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest import mock

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from qdrant_client import QdrantClient

from Backend import search_engine
from Backend.api import search_routes
from Backend.api.app import create_app
from Backend.config import EMBED_DIM
from Backend.search_engine import BM25, HybridSearcher, build_documents, rrf_fuse, tokenize
from Backend.storage.indexer import index_chunks

COLLECTION = "test_search_items"


def chunk(item_id, text, idx=0, title="", cve=None):
    cid = f"{item_id}-{idx}"
    return {
        "Chunk_ID": cid, "Item_ID": item_id, "Tier": 1, "Chunk_Index": idx, "Text": text,
        "Title": title or item_id, "Source_URL": f"https://example.com/{item_id}", "CVE_ID": cve,
        "Source_Type": "NVD", "Chunk_Hash": hashlib.md5(text.encode()).hexdigest(),
        "Point_ID": str(uuid.UUID(hashlib.md5(cid.encode()).hexdigest())),
    }


CHUNKS = [
    chunk("citrix", "NetScaler Gateway leaks session tokens from memory, bypassing multi-factor authentication.",
          title="Citrix Bleed", cve="CVE-2023-4966"),
    chunk("citrix", "Proof of concept: send an oversized Host header to the OpenID configuration endpoint.",
          idx=1, title="Citrix Bleed", cve="CVE-2023-4966"),
    chunk("frida", "Frida script hooks the root detection check so the app thinks the phone is not rooted.",
          title="Bypassing root detection with Frida"),
    chunk("smuggling", "HTTP request smuggling desync between the front-end proxy and the back-end server.",
          title="Request smuggling research"),
]
ENVELOPES = [
    {"Item_ID": "citrix", "Title": "Citrix Bleed", "Raw_Content": "already chunked", "Source_URL": "u"},
    {"Item_ID": "moveit", "Title": "MOVEit Transfer SQL injection", "CVE_ID": "CVE-2023-34362",
     "Raw_Content": "<p>An <b>SQL injection</b> in MOVEit Transfer lets attackers read the database.</p>",
     "Source_URL": "https://example.com/moveit", "Source_Type": "NVD"},
]
TRIAGED = [
    {"envelope": {"Item_ID": "citrix"}, "pre_filter": {"category": "WEB"}, "priority_score": 96.0,
     "ai_assessment": {"reasoning": "Unauthenticated session token theft."}},
]


class FakeEmbedder:
    """Deterministic vectors: texts sharing words point the same way."""

    @staticmethod
    def _vec(text):
        v = [0.0] * EMBED_DIM
        for word in text.lower().split():
            v[int(hashlib.md5(word.strip(".,:").encode()).hexdigest(), 16) % EMBED_DIM] += 1.0
        v[0] += 0.01
        return v

    def embed_documents(self, texts):
        return [self._vec(t) for t in texts]

    def embed_query(self, text):
        return self._vec(text)


class BrokenEmbedder:
    def embed_query(self, text):
        raise ConnectionError("Ollama is not running")


def write_data(tmp: Path):
    files = {}
    for name, data in (("chunks", CHUNKS), ("envelopes", ENVELOPES), ("triaged", TRIAGED)):
        p = tmp / f"{name}.json"
        p.write_text(json.dumps(data), encoding="utf-8")
        files[name] = p
    return files


def make_searcher(tmp: Path, client=None, embedder=None) -> HybridSearcher:
    f = write_data(tmp)
    return HybridSearcher(client=client, embedder=embedder, collection=COLLECTION,
                          chunks_file=f["chunks"], envelopes_file=f["envelopes"], triaged_file=f["triaged"])


class TestTokenizeAndBM25(unittest.TestCase):

    def test_cve_ids_and_versions_stay_whole(self):
        toks = tokenize("Patch CVE-2023-4966 before 13.1-49.15")
        self.assertIn("cve-2023-4966", toks)
        self.assertIn("13.1-49.15", toks)

    def test_hyphenated_words_also_match_their_parts(self):
        self.assertTrue({"use", "after", "free"} <= set(tokenize("binder use-after-free")))

    def test_stopwords_are_dropped(self):
        self.assertEqual(tokenize("the flaw in the gateway"), ["flaw", "gateway"])

    def test_rare_word_outranks_common_word(self):
        bm = BM25(["frida hook", "vulnerability one", "vulnerability two", "vulnerability three"])
        self.assertEqual(bm.rank("frida vulnerability", 4)[0][0], 0)

    def test_no_shared_words_means_no_results(self):
        self.assertEqual(BM25(["sql injection"]).rank("bluetooth", 5), [])


class TestRRF(unittest.TestCase):

    def test_item_in_both_lists_beats_item_top_in_one(self):
        scores = rrf_fuse([["a", "b"], ["c", "b"]])
        self.assertEqual(max(scores, key=scores.get), "b")

    def test_uses_k_60(self):
        self.assertAlmostEqual(rrf_fuse([["a"]])["a"], 1 / 61)


class TestBuildDocuments(unittest.TestCase):

    def test_unchunked_items_are_indexed_from_raw_text(self):
        docs = build_documents(CHUNKS, ENVELOPES)
        raw = [d for d in docs if d.item_id == "moveit"]
        self.assertEqual(len(raw), 1)
        self.assertNotIn("<b>", raw[0].text)
        self.assertIn("SQL injection", raw[0].text)

    def test_chunked_items_are_not_duplicated(self):
        docs = build_documents(CHUNKS, ENVELOPES)
        self.assertFalse(any(d.doc_id == "citrix#raw" for d in docs))


class TestKeywordSearch(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.searcher = make_searcher(Path(self.tmp.name))

    def tearDown(self):
        self.tmp.cleanup()

    def test_words_in_any_order_are_found(self):
        res = self.searcher.search("frida bypass root", mode="keyword")
        self.assertEqual(res["results"][0]["item_id"], "frida")

    def test_exact_cve_id_finds_the_item(self):
        res = self.searcher.search("CVE-2023-4966", mode="keyword")
        self.assertEqual(res["results"][0]["item_id"], "citrix")

    def test_item_not_chunked_yet_is_still_searchable(self):
        res = self.searcher.search("MOVEit sql injection", mode="keyword")
        self.assertEqual(res["results"][0]["item_id"], "moveit")

    def test_one_result_per_item(self):
        res = self.searcher.search("citrix netscaler openid host header", mode="keyword")
        ids = [r["item_id"] for r in res["results"]]
        self.assertEqual(len(ids), len(set(ids)))

    def test_result_carries_triage_info_and_snippet(self):
        top = self.searcher.search("session tokens", mode="keyword")["results"][0]
        self.assertEqual((top["scope"], top["priority_score"]), ("WEB", 96.0))
        self.assertEqual(top["rationale"], "Unauthenticated session token theft.")
        self.assertIn("session tokens", top["snippet"])
        self.assertEqual(top["url"], "https://example.com/citrix")

    def test_empty_query_returns_nothing(self):
        self.assertEqual(self.searcher.search("   ")["results"], [])

    def test_data_change_is_picked_up(self):
        self.searcher.search("frida", mode="keyword")
        chunks_file = self.searcher.files[0]
        extra = CHUNKS + [chunk("blastpass", "Zero-click iMessage exploit via a malicious WebP image.")]
        chunks_file.write_text(json.dumps(extra), encoding="utf-8")
        res = self.searcher.search("imessage webp", mode="keyword")
        self.assertEqual(res["results"][0]["item_id"], "blastpass")


class TestHybridSearch(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.client = QdrantClient(":memory:")
        index_chunks(CHUNKS, self.client, FakeEmbedder(), collection=COLLECTION)

    def tearDown(self):
        self.tmp.cleanup()

    def test_hybrid_uses_both_rankings(self):
        s = make_searcher(Path(self.tmp.name), self.client, FakeEmbedder())
        res = s.search("frida root detection", mode="hybrid")
        top = res["results"][0]
        self.assertEqual(res["mode"], "hybrid")
        self.assertEqual(top["item_id"], "frida")
        self.assertEqual((top["keyword_rank"], top["semantic_rank"]), (1, 1))

    def test_unrelated_meaning_matches_are_dropped(self):
        # Meaning search returns every indexed item; only close ones may join keyword hits
        s = make_searcher(Path(self.tmp.name), self.client, FakeEmbedder())
        with mock.patch.object(search_engine, "SEMANTIC_ONLY_TOP", 1):
            res = s.search("frida root detection", mode="hybrid")
        self.assertEqual([r["item_id"] for r in res["results"]], ["frida"])

    def test_semantic_only_mode(self):
        s = make_searcher(Path(self.tmp.name), self.client, FakeEmbedder())
        res = s.search("request smuggling desync", mode="semantic")
        self.assertEqual(res["mode"], "semantic")
        self.assertEqual(res["results"][0]["item_id"], "smuggling")
        self.assertIsNone(res["results"][0]["keyword_rank"])

    def test_falls_back_to_keyword_when_ollama_is_down(self):
        s = make_searcher(Path(self.tmp.name), self.client, BrokenEmbedder())
        res = s.search("frida root detection", mode="hybrid")
        self.assertEqual(res["mode"], "keyword")
        self.assertIn("unavailable", res["note"])
        self.assertEqual(res["results"][0]["item_id"], "frida")

    def test_semantic_request_without_qdrant_still_answers(self):
        s = make_searcher(Path(self.tmp.name))
        res = s.search("frida", mode="semantic")
        self.assertEqual(res["mode"], "keyword")
        self.assertTrue(res["results"])


class TestSearchEndpoint(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.searcher = make_searcher(Path(cls.tmp.name))
        cls.patch = mock.patch.object(search_routes, "_searcher", cls.searcher)
        cls.patch.start()
        cls.client = create_app().test_client()

    @classmethod
    def tearDownClass(cls):
        cls.patch.stop()
        cls.tmp.cleanup()

    def test_search_returns_results(self):
        resp = self.client.get("/api/search?q=frida+root&mode=keyword")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json()["results"][0]["item_id"], "frida")

    def test_limit_is_applied(self):
        resp = self.client.get("/api/search?q=the+gateway+frida+smuggling+sql&mode=keyword&limit=1")
        self.assertEqual(len(resp.get_json()["results"]), 1)

    def test_missing_query_is_400(self):
        self.assertEqual(self.client.get("/api/search").status_code, 400)

    def test_bad_mode_is_400(self):
        self.assertEqual(self.client.get("/api/search?q=x&mode=magic").status_code, 400)

    def test_bad_limit_is_400(self):
        self.assertEqual(self.client.get("/api/search?q=x&limit=lots").status_code, 400)


if __name__ == "__main__":
    unittest.main(verbosity=2)
