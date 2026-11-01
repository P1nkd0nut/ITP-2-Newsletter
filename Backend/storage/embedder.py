"""
Ollama embedding client for GroundedCVE (Task 2.3).

nomic-embed-text expects a task prefix on every input: "search_document: " for
text being indexed and "search_query: " for the text used to search it.
"""
from typing import List, Sequence

import requests

from Backend.config import EMBED_DIM, EMBED_MODEL, OLLAMA_HOST

DOCUMENT_PREFIX = "search_document: "
QUERY_PREFIX = "search_query: "


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
