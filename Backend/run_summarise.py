"""
GroundedCVE Grounded Summary CLI (Task 3.1 + 3.2).

For each top-ranked in-scope item: retrieve its own chunks (Qdrant, or
latest_chunks.json if Qdrant is down), have the LLM write a card from them,
and run the card through the verification gate. PASSED cards go to
grounded_cards.json, which the dashboard digest and Telegram digest publish
from. Quarantined cards are logged to quarantine_log.jsonl and not published.

Uses OpenRouter (OPENROUTER_API_KEY in .env), or a local Ollama model with --ollama-model.

Usage:
    python Backend/run_summarise.py                   # top 10 in-scope items from the last 7 days
    python Backend/run_summarise.py --top 20 --days 0 # top 20 regardless of date
    python Backend/run_summarise.py --force           # rewrite cards even if the source is unchanged
"""
import argparse
import json
import logging
import sys
from pathlib import Path

# Add project root to sys.path so Backend modules import cleanly
ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from Backend.config import CHUNKS_FILE, GROUNDED_CARDS_FILE, QUARANTINE_LOG_FILE, STAGING_DIR
from Backend.ingestion.models import StagingEnvelope
from Backend.ingestion.recheck_policy import age_days
from Backend.storage.indexer import ChunkRetriever
from Backend.summarisation import GroundedSummariser, default_llm, load_cards, log_rejected, save_cards

TRIAGED_FILE = STAGING_DIR / "triaged_candidates.json"


def select_items(candidates: list, top: int, days: int) -> list:
    """In-scope candidates by priority, optionally limited to the last `days` days."""
    picked = []
    for c in candidates:
        if not (c.get("pre_filter") or {}).get("is_in_scope"):
            continue
        if days > 0:
            age = age_days((c.get("envelope") or {}).get("Published_Date"))
            if age is None or age > days:
                continue
        picked.append(c)
    picked.sort(key=lambda c: float(c.get("priority_score", 0.0)), reverse=True)
    return picked[:top]


def make_retriever() -> ChunkRetriever:
    """Qdrant-backed retriever if Qdrant answers, else read chunks straight from the file."""
    try:
        from Backend.storage.embedder import OllamaEmbedder
        from Backend.storage.vector_db import get_client

        client = get_client()
        client.info()
        return ChunkRetriever(client=client, embedder=OllamaEmbedder())
    except Exception as e:
        print(f"Qdrant not reachable ({e.__class__.__name__}); reading chunks from {CHUNKS_FILE.name}")
        return ChunkRetriever()


def main() -> int:
    ap = argparse.ArgumentParser(description="Write grounded cards and gate them before publishing")
    ap.add_argument("--top", type=int, default=10, help="number of top-ranked items to summarise")
    ap.add_argument("--days", type=int, default=7, help="only items published in the last N days (0 = any date)")
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
    items = select_items(candidates, args.top, args.days)
    summariser = GroundedSummariser(llm, make_retriever())
    cards = load_cards()
    rejected, counts = [], {"PASSED": 0, "QUARANTINED": 0, "ERROR": 0, "UNCHANGED": 0}

    for c in items:
        env = StagingEnvelope.model_validate(c["envelope"])
        prev = cards.get(env.Item_ID)
        if prev and prev.get("Content_Hash") == env.Content_Hash and not args.force:
            counts["UNCHANGED"] += 1
            continue

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
          f"{counts['ERROR']} errors, {counts['UNCHANGED']} unchanged.")
    print(f"Published cards: {GROUNDED_CARDS_FILE}")
    if rejected:
        print(f"Rejected cards logged to: {QUARANTINE_LOG_FILE}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
