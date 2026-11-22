"""
Offline tests for dense + sparse (BM25) hybrid search with RRF fusion (Task 2.3).

The Qdrant client and both embedders are mocked, so nothing here touches live
Ollama, Qdrant or fastembed. index_chunks is exercised against an in-process
QdrantClient(":memory:") to assert both named vectors are written; the hybrid
retrieval path asserts the Query API call shape (prefetch + FusionQuery RRF).

Run:
    python -m pytest Testing/test_hybrid_search.py -v
"""
import hashlib
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from qdrant_client import QdrantClient
from qdrant_client.models import Fusion, FusionQuery, Prefetch, SparseVector

from Backend.chunking.models import Chunk
from Backend.config import EMBED_DIM
from Backend.storage.indexer import ChunkRetriever, index_chunks
from Backend.storage.init_qdrant import DENSE_VECTOR_NAME, SPARSE_VECTOR_NAME

COLLECTION = "test_hybrid_items"

SUMMARY = "CVE-2023-4966 is a buffer over-read in NetScaler ADC leaking session tokens."
POC = "curl -k -s https://target-gateway.com/oauth/idp/.well-known/openid-configuration"


def make_chunk(item_id, text, tier=1, index=0) -> dict:
    return Chunk(
        Chunk_ID=f"{item_id}::t{tier}::{index:03d}", Item_ID=item_id, Tier=tier, Chunk_Index=index,
        Text=text, Source_Type="NVD", Source_URL="https://example.com", Title=item_id,
    ).to_dict()


CHUNKS = [
    make_chunk("citrix", SUMMARY, tier=1),
    make_chunk("citrix", "Proof of concept:\n" + POC, tier=2),
]


class FakeEmbedder:
    """Deterministic 768-dim dense vectors; no network."""

    @staticmethod
    def _vec(text):
        v = [0.0] * EMBED_DIM
        for word in text.lower().split():
            v[int(hashlib.md5(word.encode()).hexdigest(), 16) % EMBED_DIM] += 1.0
        v[0] += 0.01  # never all zeros
        return v

    def embed_documents(self, texts):
        return [self._vec(t) for t in texts]

    def embed_query(self, text):
        return self._vec(text)


class FakeSparseEmbedder:
    """Deterministic sparse vectors; never loads fastembed."""

    @staticmethod
    def _sparse(text):
        indices, values = [], []
        for word in set(text.lower().split()):
            indices.append(int(hashlib.md5(word.encode()).hexdigest(), 16) % 100000)
            values.append(1.0)
        return SparseVector(indices=indices or [0], values=values or [0.01])

    def sparse_documents(self, texts):
        return [self._sparse(t) for t in texts]

    def sparse_query(self, text):
        return self._sparse(text)


class TestHybridIndexing(unittest.TestCase):
    def setUp(self):
        self.client = QdrantClient(":memory:")
        self.embedder = FakeEmbedder()
        self.sparse = FakeSparseEmbedder()

    def test_writes_both_dense_and_sparse_vectors(self):
        index_chunks(CHUNKS, self.client, self.embedder, collection=COLLECTION,
                     sparse_embedder=self.sparse)
        points = self.client.retrieve(
            COLLECTION, ids=[c["Point_ID"] for c in CHUNKS], with_vectors=True)
        self.assertEqual(len(points), 2)
        for p in points:
            self.assertIn(DENSE_VECTOR_NAME, p.vector)
            self.assertIn(SPARSE_VECTOR_NAME, p.vector)

    def test_dense_only_when_no_sparse_embedder(self):
        index_chunks(CHUNKS, self.client, self.embedder, collection=COLLECTION)
        points = self.client.retrieve(
            COLLECTION, ids=[c["Point_ID"] for c in CHUNKS], with_vectors=True)
        self.assertEqual(len(points), 2)
        for p in points:
            self.assertIn(DENSE_VECTOR_NAME, p.vector)
            self.assertNotIn(SPARSE_VECTOR_NAME, p.vector)

    def test_dense_only_points_get_sparse_vector_on_next_run(self):
        index_chunks(CHUNKS, self.client, self.embedder, collection=COLLECTION)
        stats = index_chunks(CHUNKS, self.client, self.embedder, collection=COLLECTION,
                             sparse_embedder=self.sparse)
        self.assertEqual(stats["embedded"], 2)
        points = self.client.retrieve(
            COLLECTION, ids=[c["Point_ID"] for c in CHUNKS], with_vectors=True)
        for p in points:
            self.assertIn(SPARSE_VECTOR_NAME, p.vector)
        # once both vectors are stored, unchanged chunks are skipped again
        stats = index_chunks(CHUNKS, self.client, self.embedder, collection=COLLECTION,
                             sparse_embedder=self.sparse)
        self.assertEqual(stats["skipped"], 2)

    def test_dense_only_retrieval_still_succeeds(self):
        index_chunks(CHUNKS, self.client, self.embedder, collection=COLLECTION)
        retriever = ChunkRetriever(self.client, self.embedder, collection=COLLECTION)
        chunks, mode = retriever.retrieve("citrix", "session token leak")
        self.assertEqual(mode, "qdrant")
        self.assertEqual({c["Item_ID"] for c in chunks}, {"citrix"})
        self.assertEqual([c["Tier"] for c in chunks], [1, 2])  # document order preserved


class TestHybridRetrievalCallShape(unittest.TestCase):
    def test_from_qdrant_issues_prefetch_fusion_rrf(self):
        client = mock.Mock()
        hit = mock.Mock()
        hit.payload = dict(CHUNKS[0])
        client.query_points.return_value = mock.Mock(points=[hit])

        retriever = ChunkRetriever(client, FakeEmbedder(), collection=COLLECTION,
                                   sparse_embedder=FakeSparseEmbedder())
        chunks, mode = retriever.retrieve("citrix", "session token leak", limit=8)

        self.assertEqual(mode, "qdrant")
        self.assertEqual(client.query_points.call_count, 1)
        kwargs = client.query_points.call_args.kwargs

        prefetch = kwargs["prefetch"]
        self.assertEqual(len(prefetch), 2)
        self.assertTrue(all(isinstance(p, Prefetch) for p in prefetch))
        self.assertEqual({p.using for p in prefetch}, {DENSE_VECTOR_NAME, SPARSE_VECTOR_NAME})

        query = kwargs["query"]
        self.assertIsInstance(query, FusionQuery)
        self.assertEqual(query.fusion, Fusion.RRF)
        self.assertIsNotNone(kwargs["query_filter"])

    def test_falls_back_to_dense_when_fusion_fails(self):
        client = mock.Mock()
        hit = mock.Mock()
        hit.payload = dict(CHUNKS[0])

        def query_points(**kwargs):
            if "prefetch" in kwargs:
                raise RuntimeError("fusion unsupported")
            return mock.Mock(points=[hit])

        client.query_points.side_effect = query_points
        retriever = ChunkRetriever(client, FakeEmbedder(), collection=COLLECTION,
                                   sparse_embedder=FakeSparseEmbedder())
        chunks, mode = retriever.retrieve("citrix", "q", limit=8)

        self.assertEqual(mode, "qdrant")
        self.assertEqual(client.query_points.call_count, 2)  # hybrid attempt, then dense fallback
        self.assertEqual({c["Item_ID"] for c in chunks}, {"citrix"})


if __name__ == "__main__":
    unittest.main()
