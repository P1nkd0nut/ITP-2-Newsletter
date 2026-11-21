"""
GroundedCVE Grounded Summary CLI (Task 3.1 + 3.2).

For every in-scope item that is new or changed this week (published, first
seen or changed in the last 7 days), highest priority first: retrieve its own chunks (Qdrant, or
latest_chunks.json if Qdrant is down), have the LLM write a card from them,
and run the card through the verification gate. PASSED cards go to
grounded_cards.json, which the dashboard digest and Telegram digest publish
from. Quarantined cards are logged to quarantine_log.jsonl and not published.

Uses OpenRouter (OPENROUTER_API_KEY in .env), or a local Ollama model with --ollama-model.

Usage:
    python Backend/run_summarise.py                   # every in-scope item new or changed in the last 7 days (up to 50 cards)
    python Backend/run_summarise.py --top 0 --days 0  # every in-scope item, any date (catch-up of the whole backlog)
    python Backend/run_summarise.py --force           # rewrite cards even if the source is unchanged
"""
import argparse
import json
import logging
import sys
import time
from pathlib import Path
from typing import Dict, Optional

# Add project root to sys.path so Backend modules import cleanly
ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from Backend.config import CHUNKS_FILE, GROUNDED_CARDS_FILE, QUARANTINE_LOG_FILE, STAGING_DIR
from Backend.ingestion.models import StagingEnvelope
from Backend.ingestion.recheck_policy import age_days
from Backend.storage.indexer import ChunkRetriever
from Backend.summarisation import GroundedSummariser, default_llm, load_cards, log_rejected, save_cards
from Backend.summarisation.summariser import nvd_excerpt_hash

TRIAGED_FILE = STAGING_DIR / "triaged_candidates.json"


def last_activity_age(envelope: dict) -> Optional[int]:
    """
    Days since the item was last new to GroundedCVE: the most recent of its
    publication, the run that first fetched it and the run that last saw it
    change. An advisory picked up today counts as this week's news even if its
    publisher dated it earlier.
    """
    ages = [age_days(envelope.get(k)) for k in ("Published_Date", "First_Seen", "Last_Changed")]
    ages = [a for a in ages if a is not None]
    return min(ages) if ages else None


def select_items(candidates: list, top: int, days: int) -> list:
    """
    In-scope candidates by priority. With days > 0, only items published, first
    seen or changed in the last `days` days. top = 0 means no limit.
    """
    picked = []
    for c in candidates:
        if not (c.get("pre_filter") or {}).get("is_in_scope"):
            continue
        if days > 0:
            age = last_activity_age(c.get("envelope") or {})
            if age is None or age > days:
                continue
        picked.append(c)
    picked.sort(key=lambda c: float(c.get("priority_score", 0.0)), reverse=True)
    return picked[:top] if top > 0 else picked


def load_quarantined(path: Path = QUARANTINE_LOG_FILE) -> Dict[str, dict]:
    """Latest quarantine-log record per item (QUARANTINED or ERROR)."""
    latest: Dict[str, dict] = {}
    if not path.exists():
        return latest
    for line in path.read_text(encoding="utf-8").splitlines():
        try:
            rec = json.loads(line)
        except ValueError:
            continue
        if rec.get("Item_ID"):
            latest[rec["Item_ID"]] = rec
    return latest


def same_source(record: Optional[dict], env: StagingEnvelope) -> bool:
    """True when a stored card or log record was written from the item's current source."""
    return bool(
        record
        and record.get("Content_Hash") == env.Content_Hash
        and record.get("nvd_record_hash") == nvd_excerpt_hash(env)
    )


def make_retriever() -> ChunkRetriever:
    """Qdrant-backed retriever if Qdrant answers, else read chunks straight from the file."""
    try:
        from Backend.storage.embedder import OllamaEmbedder, SparseEmbedder
        from Backend.storage.vector_db import get_client

        client = get_client()
        client.info()
        # Sparse (BM25) enables hybrid fusion; if fastembed is unavailable the
        # retriever falls back to dense-only, so build it best-effort.
        try:
            sparse_embedder = SparseEmbedder()
        except Exception as se:
            print(f"Sparse embedder unavailable ({se.__class__.__name__}); retrieving dense-only")
            sparse_embedder = None
        return ChunkRetriever(client=client, embedder=OllamaEmbedder(), sparse_embedder=sparse_embedder)
    except Exception as e:
        print(f"Qdrant not reachable ({e.__class__.__name__}); reading chunks from {CHUNKS_FILE.name}")
        return ChunkRetriever()


def main() -> int:
    ap = argparse.ArgumentParser(description="Write grounded cards and gate them before publishing")
    ap.add_argument("--top", type=int, default=50,
                    help="most cards to write in one run (0 = no limit); items left over are written on the next run")
    ap.add_argument("--days", type=int, default=7,
                    help="only items published, first seen or changed in the last N days (0 = any date)")
    ap.add_argument("--pause", type=float, default=1.0,
                    help="seconds to wait between cards, to stay under the LLM provider's rate limit")
    ap.add_argument("--ollama-model", help="use this local Ollama model when OPENROUTER_API_KEY is not set")
    ap.add_argument("--force", action="store_true", help="rewrite cards whose source has not changed")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()
    logging.basicConfig(level=logging.INFO if args.verbose else logging.WARNING)

    if not TRIAGED_FILE.exists():
        print(f"{TRIAGED_FILE} not found. Run Backend/run_triage.py first.")
        return 2
    llm = default_llm(args.ollama_model)
    if llm is None:
        print("No LLM configured: set OPENROUTER_API_KEY in .env or pass --ollama-model.")
        return 2

    candidates = json.loads(TRIAGED_FILE.read_text(encoding="utf-8"))
    items = select_items(candidates, 0, args.days)
    summariser = GroundedSummariser(llm, make_retriever())
    cards = load_cards()
    quarantined = load_quarantined()
    rejected = []
    counts = {"PASSED": 0, "QUARANTINED": 0, "ERROR": 0, "UNCHANGED": 0, "STILL_QUARANTINED": 0, "DEFERRED": 0}
    written = 0

    for c in items:
        env = StagingEnvelope.model_validate(c["envelope"])
        if not args.force:
            if same_source(cards.get(env.Item_ID), env):
                counts["UNCHANGED"] += 1
                continue
            # A card the gate rejected twice is not retried until its source changes
            last = quarantined.get(env.Item_ID)
            if last and last.get("status") == "QUARANTINED" and same_source(last, env):
                counts["STILL_QUARANTINED"] += 1
                continue
        if args.top and written >= args.top:
            counts["DEFERRED"] += 1
            continue
        if written and args.pause > 0:
            time.sleep(args.pause)
        written += 1

        record = summariser.summarise(env)
        counts[record["status"]] += 1
        if record["status"] == "PASSED":
            cards[env.Item_ID] = record
        else:
            cards.pop(env.Item_ID, None)  # an older card no longer matches the source
            rejected.append(record)
        reasons = "; ".join(f"{f['check']} {f['value']}" for f in (record.get("verification") or {}).get("failures", []))
        print(f"{record['status']:<11} {env.Item_ID}  {reasons or record.get('error', '')}")

    save_cards(cards)
    log_rejected(rejected)
    print(f"\n{len(items)} items: {counts['PASSED']} passed, {counts['QUARANTINED']} quarantined, "
          f"{counts['ERROR']} errors, {counts['UNCHANGED']} unchanged, "
          f"{counts['STILL_QUARANTINED']} still quarantined (source unchanged).")
    if counts["DEFERRED"]:
        print(f"{counts['DEFERRED']} items left for the next run (--top {args.top} cards per run).")
    print(f"Published cards: {GROUNDED_CARDS_FILE}")
    if rejected:
        print(f"Rejected cards logged to: {QUARANTINE_LOG_FILE}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
