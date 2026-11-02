"""
Ollama embedding client for GroundedCVE (Task 2.3).

nomic-embed-text expects a task prefix on every input: "search_document: " for
text being indexed and "search_query: " for the text used to search it.

SparseEmbedder adds the BM25 (sparse lexical) half of hybrid search via
fastembed's SparseTextEmbedding ("Qdrant/bm25"). The fastembed model is loaded
lazily and reused, so importing this module never downloads a model and tests
that mock SparseEmbedder stay offline.
"""
from typing import List, Sequence

import requests
from qdrant_client.models import SparseVector

from Backend.config import EMBED_DIM, EMBED_MODEL, OLLAMA_HOST

DOCUMENT_PREFIX = "search_document: "
QUERY_PREFIX = "search_query: "

SPARSE_MODEL = "Qdrant/bm25"


class OllamaEmbedder:
    """Calls Ollama's /api/embed endpoint in batches."""

    def __init__(self, host: str = OLLAMA_HOST, model: str = EMBED_MODEL, batch_size: int = 16, timeout: int = 120):
        self.host = host.rstrip("/")
        self.model = model
        self.batch_size = batch_size
        self.timeout = timeout

    def _embed(self, inputs: Sequence[str]) -> List[List[float]]:
        vectors: List[List[float]] = []
        for i in range(0, len(inputs), self.batch_size):
            batch = list(inputs[i : i + self.batch_size])
            resp = requests.post(
                f"{self.host}/api/embed",
                json={"model": self.model, "input": batch},
                timeout=self.timeout,
            )
            resp.raise_for_status()
            embeddings = resp.json().get("embeddings") or []
            if len(embeddings) != len(batch):
                raise RuntimeError(f"Ollama returned {len(embeddings)} embeddings for {len(batch)} inputs")
            for vec in embeddings:
                if len(vec) != EMBED_DIM:
                    raise RuntimeError(f"Expected {EMBED_DIM}-dim vectors from {self.model}, got {len(vec)}")
            vectors.extend(embeddings)
        return vectors

    def embed_documents(self, texts: Sequence[str]) -> List[List[float]]:
        return self._embed([DOCUMENT_PREFIX + t for t in texts])

    def embed_query(self, text: str) -> List[float]:
        return self._embed([QUERY_PREFIX + text])[0]


class SparseEmbedder:
    """
    BM25 sparse embeddings via fastembed. The model is loaded once on first use
    (not at import time) and reused for every call, so mocked tests never hit the
    network and the pipeline only pays the load cost when sparse search is wanted.
    """

    def __init__(self, model_name: str = SPARSE_MODEL):
        self.model_name = model_name
        self._model = None

    def _load(self):
        if self._model is None:
            from fastembed import SparseTextEmbedding

            self._model = SparseTextEmbedding(model_name=self.model_name)
        return self._model

    @staticmethod
    def _to_sparse_vector(emb) -> SparseVector:
        return SparseVector(indices=emb.indices.tolist(), values=emb.values.tolist())

    def sparse_documents(self, texts: Sequence[str]) -> List[SparseVector]:
        model = self._load()
        return [self._to_sparse_vector(e) for e in model.embed(list(texts))]

    def sparse_query(self, text: str) -> SparseVector:
        model = self._load()
        return self._to_sparse_vector(next(iter(model.query_embed(text))))
