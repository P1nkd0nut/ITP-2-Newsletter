"""
Chunk indexing and per-item retrieval for GroundedCVE (Task 2.3).

index_chunks() embeds chunks from latest_chunks.json with nomic-embed-text and
upserts them into the Qdrant items collection. Point IDs are deterministic
(Chunk.point_id), so re-running only re-embeds chunks whose text changed.

ChunkRetriever.retrieve() returns an item's own chunks for the summariser:
from Qdrant when it is reachable, otherwise straight from latest_chunks.json.
"""
import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from qdrant_client.models import (
    FieldCondition,
    Filter,
    Fusion,
    FusionQuery,
    HasIdCondition,
    MatchAny,
    MatchValue,
    PayloadSchemaType,
    PointStruct,
    Prefetch,
)

from Backend.config import CHUNKS_FILE, QDRANT_COLLECTION_ITEMS
from Backend.storage.init_qdrant import DENSE_VECTOR_NAME, SPARSE_VECTOR_NAME, ensure_collection

logger = logging.getLogger(__name__)


def load_chunks(path: Path = CHUNKS_FILE) -> List[Dict[str, Any]]:
    if not path.exists():
        return []
    return json.loads(path.read_text(encoding="utf-8"))


def index_chunks(
    chunks: Sequence[Dict[str, Any]],
    client,
    embedder,
    collection: str = QDRANT_COLLECTION_ITEMS,
    force: bool = False,
    sparse_embedder=None,
) -> Dict[str, int]:
    """
    Embed and upsert chunks. Chunks already stored with the same Chunk_Hash are
    skipped unless force=True. Points left over from an item's older, longer
    version are deleted so retrieval never returns stale text.

    When sparse_embedder is given, each point carries both the dense and the
    "sparse" (BM25) named vector; without it, points are written dense-only so
    existing callers keep working.
    """
    ensure_collection(client, collection)
    client.create_payload_index(collection, field_name="Item_ID", field_schema=PayloadSchemaType.KEYWORD)

    ids = [c["Point_ID"] for c in chunks]
    existing: Dict[str, str] = {}
    if ids and not force:
        for p in client.retrieve(collection, ids=ids, with_payload=["Chunk_Hash"], with_vectors=False):
            existing[str(p.id)] = (p.payload or {}).get("Chunk_Hash", "")

    todo = [c for c in chunks if existing.get(c["Point_ID"]) != c["Chunk_Hash"]]
    if todo:
        texts = [c["Text"] for c in todo]
        vectors = embedder.embed_documents(texts)
        sparse_vectors = sparse_embedder.sparse_documents(texts) if sparse_embedder is not None else None
        points = []
        for i, (c, vec) in enumerate(zip(todo, vectors)):
            vector = {DENSE_VECTOR_NAME: vec}
            if sparse_vectors is not None:
                vector[SPARSE_VECTOR_NAME] = sparse_vectors[i]
            points.append(PointStruct(id=c["Point_ID"], vector=vector, payload=dict(c)))
        client.upsert(collection_name=collection, points=points, wait=True)

    item_ids = sorted({c["Item_ID"] for c in chunks})
    if item_ids:
        client.delete(
            collection_name=collection,
            points_selector=Filter(
                must=[FieldCondition(key="Item_ID", match=MatchAny(any=item_ids))],
                must_not=[HasIdCondition(has_id=ids)],
            ),
            wait=True,
        )

    return {"total": len(chunks), "embedded": len(todo), "skipped": len(chunks) - len(todo)}


def _order(chunk: Dict[str, Any]) -> Tuple[int, int]:
    return int(chunk.get("Tier", 1)), int(chunk.get("Chunk_Index", 0))


class ChunkRetriever:
    """Fetches the chunks a card may be written from. Only the item's own chunks are ever returned."""

    def __init__(self, client=None, embedder=None, chunks_file: Path = CHUNKS_FILE,
                 collection: str = QDRANT_COLLECTION_ITEMS, sparse_embedder=None):
        self.client = client
        self.embedder = embedder
        self.sparse_embedder = sparse_embedder
        self.collection = collection
        self._file_chunks: Optional[Dict[str, List[Dict[str, Any]]]] = None
        self.chunks_file = chunks_file

    def _from_file(self, item_id: str) -> List[Dict[str, Any]]:
        if self._file_chunks is None:
            self._file_chunks = {}
            for c in load_chunks(self.chunks_file):
                self._file_chunks.setdefault(c["Item_ID"], []).append(c)
        return sorted(self._file_chunks.get(item_id, []), key=_order)

    def _from_qdrant(self, item_id: str, query: str, limit: int) -> List[Dict[str, Any]]:
        vec = self.embedder.embed_query(query)
        item_filter = Filter(must=[FieldCondition(key="Item_ID", match=MatchValue(value=item_id))])

        if self.sparse_embedder is not None:
            try:
                sparse_vec = self.sparse_embedder.sparse_query(query)
                hits = self.client.query_points(
                    collection_name=self.collection,
                    prefetch=[
                        Prefetch(query=vec, using=DENSE_VECTOR_NAME, limit=limit),
                        Prefetch(query=sparse_vec, using=SPARSE_VECTOR_NAME, limit=limit),
                    ],
                    query=FusionQuery(fusion=Fusion.RRF),
                    query_filter=item_filter,
                    limit=limit,
                    with_payload=True,
                ).points
                return [h.payload for h in hits if h.payload]
            except Exception as e:
                logger.warning(f"Hybrid fusion failed for {item_id} ({e}); using dense-only query")

        hits = self.client.query_points(
            collection_name=self.collection,
            query=vec,
            using=DENSE_VECTOR_NAME,
            query_filter=item_filter,
            limit=limit,
            with_payload=True,
        ).points
        return [h.payload for h in hits if h.payload]

    def retrieve(self, item_id: str, query: str, limit: int = 8) -> Tuple[List[Dict[str, Any]], str]:
        """Returns (chunks in document order, "qdrant" or "file")."""
        if self.client is not None and self.embedder is not None:
            try:
                chunks = self._from_qdrant(item_id, query, limit)
                if chunks:
                    return sorted(chunks, key=_order), "qdrant"
            except Exception as e:
                logger.warning(f"Qdrant retrieval failed for {item_id} ({e}); using {self.chunks_file.name}")
        return self._from_file(item_id)[:limit], "file"
