"""
Hybrid search over every collected item (project plan Tasks 2.3 and 3.3).

Two searches run side by side and their rankings are merged:
  1. Keyword search (BM25): items containing the query's words score higher,
     rare words count more than common ones, and long texts don't win by length.
     Exact tokens such as CVE IDs and version strings are kept whole.
  2. Meaning search: the nomic-embed-text vectors run_indexing.py already
     stores in Qdrant, so "steal session cookies" can find "cookie prefix bypass".

Reciprocal Rank Fusion (RRF, k=60) merges the two lists: items that rank high
in both come first. Results are per item, not per chunk. If Qdrant or Ollama
can't be reached, search falls back to keyword-only and says so.

It reads latest_chunks.json, latest_envelopes.json and triaged_candidates.json,
so items not picked for the weekly digest stay findable.
"""
import html
import json
import logging
import math
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from Backend.config import CHUNKS_FILE, QDRANT_COLLECTION_ITEMS, STAGING_DIR
from Backend.storage.init_qdrant import DENSE_VECTOR_NAME

logger = logging.getLogger(__name__)


# ============================================================ keyword search (BM25)

# Keeps "cve-2024-3400", "13.1-49.15", "use-after-free" and "run-as" as single tokens.
TOKEN_RE = re.compile(r"[a-z0-9]+(?:[-._][a-z0-9]+)*")

STOPWORDS = frozenset(
    "a an and are as at be by can could for from has have how in into is it its of on or "
    "that the their this to was were what when where which who will with without".split()
)


def tokenize(text: str) -> List[str]:
    """Lowercase word tokens without stopwords. Hyphenated tokens also add their parts,
    so "use-after-free" matches a query for "use after free" and vice versa."""
    tokens: List[str] = []
    for tok in TOKEN_RE.findall(text.lower()):
        if tok in STOPWORDS:
            continue
        tokens.append(tok)
        if "-" in tok and not tok.startswith("cve-"):
            tokens.extend(p for p in tok.split("-") if p and p not in STOPWORDS)
    return tokens


class BM25:
    """Okapi BM25 over a fixed list of texts. k1 and b are the standard defaults."""

    def __init__(self, texts: Sequence[str], k1: float = 1.5, b: float = 0.75):
        self.k1 = k1
        self.b = b
        self.term_freqs: List[Counter] = [Counter(tokenize(t)) for t in texts]
        self.lengths = [sum(tf.values()) for tf in self.term_freqs]
        self.avg_len = (sum(self.lengths) / len(self.lengths)) if self.lengths else 0.0
        doc_freq: Counter = Counter()
        for tf in self.term_freqs:
            doc_freq.update(tf.keys())
        n = len(self.term_freqs)
        # +1 inside the log keeps every weight positive, even for words in most documents
        self.idf: Dict[str, float] = {
            term: math.log(1 + (n - df + 0.5) / (df + 0.5)) for term, df in doc_freq.items()
        }

    def score(self, query: str, index: int) -> float:
        tf = self.term_freqs[index]
        length_norm = self.k1 * (1 - self.b + self.b * self.lengths[index] / (self.avg_len or 1))
        total = 0.0
        for term in set(tokenize(query)):
            f = tf.get(term, 0)
            if f:
                total += self.idf[term] * f * (self.k1 + 1) / (f + length_norm)
        return total

    def rank(self, query: str, limit: int) -> List[Tuple[int, float]]:
        """(document index, score) for documents matching at least one query word, best first."""
        scored = [(i, self.score(query, i)) for i in range(len(self.term_freqs))]
        scored = [(i, s) for i, s in scored if s > 0]
        scored.sort(key=lambda x: x[1], reverse=True)
        return scored[:limit]


# ============================================================ hybrid search

ENVELOPES_FILE = STAGING_DIR / "latest_envelopes.json"
TRIAGED_FILE = STAGING_DIR / "triaged_candidates.json"

RRF_K = 60                # constant from the project plan (Task 2.3)
CANDIDATE_DEPTH = 50      # how many chunks each ranking contributes before fusion
SEMANTIC_ONLY_TOP = 5     # in hybrid mode, meaning-only matches must be in the top 5 by meaning
RAW_DOC_MAX_CHARS = 5000  # raw text indexed for an item that has no chunks yet
SNIPPET_CHARS = 240
MODES = ("hybrid", "keyword", "semantic")


@dataclass
class Document:
    doc_id: str
    item_id: str
    title: str
    text: str
    url: str = ""
    cve_id: Optional[str] = None
    source_type: str = ""


def _read_json(path: Path) -> list:
    if not path.exists():
        return []
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        logger.warning(f"Could not read {path}")
        return []


def _plain_text(raw: str) -> str:
    """Rough tag strip for raw HTML so BM25 indexes words, not markup."""
    text = re.sub(r"<(script|style)\b.*?</\1>", " ", raw or "", flags=re.S | re.I)
    text = re.sub(r"<[^>]+>", " ", text)
    return re.sub(r"\s+", " ", html.unescape(text)).strip()


def build_documents(chunks: List[Dict[str, Any]], envelopes: List[Dict[str, Any]]) -> List[Document]:
    """One document per chunk. Items with no chunks yet are indexed from their raw text."""
    docs = [
        Document(
            doc_id=c["Chunk_ID"],
            item_id=c["Item_ID"],
            title=c.get("Title") or "",
            text=c.get("Text") or "",
            url=c.get("Source_URL") or "",
            cve_id=c.get("CVE_ID"),
            source_type=c.get("Source_Type") or "",
        )
        for c in chunks
    ]
    chunked = {c["Item_ID"] for c in chunks}
    for e in envelopes:
        if e.get("Item_ID") in chunked:
            continue
        docs.append(Document(
            doc_id=f"{e['Item_ID']}#raw",
            item_id=e["Item_ID"],
            title=e.get("Title") or "",
            text=_plain_text(e.get("Raw_Content") or "")[:RAW_DOC_MAX_CHARS],
            url=e.get("Source_URL") or "",
            cve_id=e.get("CVE_ID"),
            source_type=str(e.get("Source_Type") or ""),
        ))
    return docs


def rrf_fuse(rankings: List[List[str]], k: int = RRF_K) -> Dict[str, float]:
    """Reciprocal Rank Fusion: each list adds 1 / (k + rank) for every id it contains."""
    scores: Dict[str, float] = {}
    for ranking in rankings:
        for rank, key in enumerate(ranking, start=1):
            scores[key] = scores.get(key, 0.0) + 1.0 / (k + rank)
    return scores


def _items_in_order(doc_hits: List[Tuple[str, Any]]) -> List[str]:
    """Collapse a chunk ranking to an item ranking: an item takes the rank of its best chunk."""
    seen: List[str] = []
    for item_id, _ in doc_hits:
        if item_id not in seen:
            seen.append(item_id)
    return seen


def make_snippet(text: str, query: str, width: int = SNIPPET_CHARS) -> str:
    """A window of `text` around the first query word it contains (or its start)."""
    flat = re.sub(r"\s+", " ", text).strip()
    low = flat.lower()
    starts = [low.find(t) for t in tokenize(query) if low.find(t) >= 0]
    start = max(0, min(starts) - width // 3) if starts else 0
    piece = flat[start:start + width]
    return ("…" if start > 0 else "") + piece + ("…" if start + width < len(flat) else "")


class HybridSearcher:
    """
    client / embedder: a QdrantClient and an embedder with embed_query(), or None
    for keyword-only search. Data files are re-read automatically when they change.
    """

    def __init__(self, client=None, embedder=None, collection: str = QDRANT_COLLECTION_ITEMS,
                 chunks_file: Path = CHUNKS_FILE, envelopes_file: Path = ENVELOPES_FILE,
                 triaged_file: Path = TRIAGED_FILE):
        self.client = client
        self.embedder = embedder
        self.collection = collection
        self.files = (chunks_file, envelopes_file, triaged_file)
        self._stamp: Optional[tuple] = None
        self.docs: List[Document] = []
        self.bm25: Optional[BM25] = None
        self.triage: Dict[str, Dict[str, Any]] = {}

    # ------------------------------------------------------------------ data

    def _file_stamp(self) -> tuple:
        return tuple((p.stat().st_mtime, p.stat().st_size) if p.exists() else None for p in self.files)

    def refresh(self, force: bool = False) -> None:
        stamp = self._file_stamp()
        if not force and stamp == self._stamp:
            return
        chunks_file, envelopes_file, triaged_file = self.files
        self.docs = build_documents(_read_json(chunks_file), _read_json(envelopes_file))
        # The CVE ID is indexed too, since a chunk's text doesn't always repeat it
        self.bm25 = BM25([f"{d.cve_id or ''} {d.title}\n{d.text}" for d in self.docs])
        self.triage = {}
        for c in _read_json(triaged_file):
            env = c.get("envelope") or {}
            self.triage[env.get("Item_ID")] = {
                "scope": (c.get("pre_filter") or {}).get("category"),
                "priority_score": c.get("priority_score"),
                "rationale": (c.get("ai_assessment") or {}).get("reasoning"),
            }
        self._stamp = stamp

    # -------------------------------------------------------------- rankings

    def keyword_ranking(self, query: str, depth: int = CANDIDATE_DEPTH) -> List[Tuple[str, Dict[str, Any]]]:
        """(item_id, hit) per matching chunk, best first."""
        self.refresh()
        hits = []
        for idx, score in self.bm25.rank(query, depth):
            d = self.docs[idx]
            hits.append((d.item_id, {"doc": d, "score": score}))
        return hits

    def semantic_ranking(self, query: str, depth: int = CANDIDATE_DEPTH) -> List[Tuple[str, Dict[str, Any]]]:
        """(item_id, hit) per chunk from Qdrant, closest first. Raises if Qdrant/Ollama fail."""
        if self.client is None or self.embedder is None:
            raise RuntimeError("semantic search is not configured")
        vec = self.embedder.embed_query(query)
        points = self.client.query_points(
            collection_name=self.collection,
            query=vec,
            using=DENSE_VECTOR_NAME,
            limit=depth,
            with_payload=True,
        ).points
        hits = []
        for p in points:
            payload = p.payload or {}
            if not payload.get("Item_ID"):
                continue
            d = Document(
                doc_id=str(payload.get("Chunk_ID") or p.id),
                item_id=payload["Item_ID"],
                title=payload.get("Title") or "",
                text=payload.get("Text") or "",
                url=payload.get("Source_URL") or "",
                cve_id=payload.get("CVE_ID"),
                source_type=payload.get("Source_Type") or "",
            )
            hits.append((d.item_id, {"doc": d, "score": float(p.score)}))
        return hits

    # ---------------------------------------------------------------- search

    def search(self, query: str, limit: int = 10, mode: str = "hybrid") -> Dict[str, Any]:
        query = (query or "").strip()
        mode = mode if mode in MODES else "hybrid"
        response: Dict[str, Any] = {"query": query, "requested_mode": mode, "mode": mode, "note": None, "results": []}
        if not query:
            response["note"] = "Empty query."
            return response

        keyword_hits: List[Tuple[str, Dict[str, Any]]] = []
        semantic_hits: List[Tuple[str, Dict[str, Any]]] = []
        if mode in ("hybrid", "keyword"):
            keyword_hits = self.keyword_ranking(query)
        if mode in ("hybrid", "semantic"):
            try:
                semantic_hits = self.semantic_ranking(query)
            except Exception as e:
                logger.warning(f"Semantic search unavailable ({e}); using keyword search only")
                response["mode"] = "keyword"
                response["note"] = "Meaning search unavailable (Qdrant/Ollama not reachable); showing keyword results only."
                if not keyword_hits:
                    keyword_hits = self.keyword_ranking(query)

        keyword_items = _items_in_order(keyword_hits)
        semantic_items = _items_in_order(semantic_hits)
        fused = rrf_fuse([r for r in (keyword_items, semantic_items) if r])
        if keyword_items and semantic_items:
            # Meaning search always returns its nearest items, related or not. In hybrid
            # mode an item with none of the query's words must be a close meaning match.
            keep = set(keyword_items) | set(semantic_items[:SEMANTIC_ONLY_TOP])
            fused = {item: score for item, score in fused.items() if item in keep}
        ordered = sorted(fused, key=lambda item: fused[item], reverse=True)[:limit]

        best_kw = {}
        for item_id, hit in keyword_hits:
            best_kw.setdefault(item_id, hit)
        best_sem = {}
        for item_id, hit in semantic_hits:
            best_sem.setdefault(item_id, hit)

        for rank, item_id in enumerate(ordered, start=1):
            hit = best_kw.get(item_id) or best_sem.get(item_id)
            doc: Document = hit["doc"]
            info = self.triage.get(item_id, {})
            response["results"].append({
                "rank": rank,
                "item_id": item_id,
                "title": doc.title,
                "cve_id": doc.cve_id,
                "source_type": doc.source_type,
                "url": doc.url,
                "scope": info.get("scope"),
                "score": round(fused[item_id], 5),
                "keyword_rank": keyword_items.index(item_id) + 1 if item_id in keyword_items else None,
                "semantic_rank": semantic_items.index(item_id) + 1 if item_id in semantic_items else None,
                "priority_score": info.get("priority_score"),
                "rationale": info.get("rationale"),
                "snippet": make_snippet(doc.text or doc.title, query),
            })
        return response


def default_searcher() -> HybridSearcher:
    """Searcher wired to the docker-compose Qdrant and Ollama; keyword-only if they're down."""
    try:
        from Backend.storage.embedder import OllamaEmbedder
        from Backend.storage.vector_db import get_client
        return HybridSearcher(client=get_client(), embedder=OllamaEmbedder(timeout=15))
    except Exception as e:
        logger.warning(f"Semantic search disabled ({e})")
        return HybridSearcher()
