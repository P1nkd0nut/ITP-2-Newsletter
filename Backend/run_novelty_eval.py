"""
Novelty Threshold Tuning (plan Task 2.4 / Task 4.1).

The novelty check skips a write-up with no CVE ID when its card is too similar
(cosine similarity on nomic-embed-text vectors) to one already published. This
script picks that similarity threshold from labelled data instead of guessing:

  1. Embed both texts of every pair in Backend/data/novelty_pairs.json, the way
     production does (published card = document, new card = query).
  2. On the 'tune' half, print the score distributions of DUPLICATE and
     DISTINCT pairs and choose the threshold that classifies them best
     (ties go to the higher threshold, so fewer new items are wrongly hidden).
  3. On the 'heldout' half, report:
       suppression rate        = duplicates caught / all duplicates
       false-suppression rate  = distinct pairs wrongly hidden / all distinct pairs
  4. Save the results and the chosen threshold to
     Backend/data/novelty_threshold.json, which the Telegram digest reads.

Needs Ollama with nomic-embed-text (docker compose up starts it).

Usage:
    python Backend/run_novelty_eval.py
    docker compose exec app python Backend/run_novelty_eval.py
"""
import json
import math
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Sequence, Tuple

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from Backend.config import DATA_DIR

PAIRS_FILE = DATA_DIR / "novelty_pairs.json"
RESULT_FILE = DATA_DIR / "novelty_threshold.json"


def cosine(a: Sequence[float], b: Sequence[float]) -> float:
    dot = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(y * y for y in b))
    return dot / (na * nb) if na and nb else 0.0


def rates(scored: List[Tuple[float, bool]], threshold: float) -> Dict[str, float]:
    """scored = [(similarity, is_duplicate)]. A pair is suppressed when similarity >= threshold."""
    dups = [s for s, d in scored if d]
    distinct = [s for s, d in scored if not d]
    caught = sum(1 for s in dups if s >= threshold)
    wrongly = sum(1 for s in distinct if s >= threshold)
    return {
        "suppression_rate": caught / len(dups) if dups else 0.0,
        "false_suppression_rate": wrongly / len(distinct) if distinct else 0.0,
        "accuracy": (caught + len(distinct) - wrongly) / len(scored) if scored else 0.0,
    }


def choose_threshold(scored: List[Tuple[float, bool]]) -> float:
    """
    The threshold with the best accuracy on the tuning pairs. Candidates sit
    halfway between neighbouring scores; ties go to the higher threshold.
    """
    scores = sorted({round(s, 4) for s, _ in scored})
    candidates = [(a + b) / 2 for a, b in zip(scores, scores[1:])] or scores
    candidates.append(scores[-1] + 1e-4)  # suppress nothing
    best = max(candidates, key=lambda t: (rates(scored, t)["accuracy"], t))
    return round(best, 4)


def histogram(values: List[float], lo: float, hi: float, bins: int = 10) -> List[str]:
    width = (hi - lo) / bins or 1.0
    counts = [0] * bins
    for v in values:
        counts[min(bins - 1, max(0, int((v - lo) / width)))] += 1
    return [f"  {lo + i * width:.3f}-{lo + (i + 1) * width:.3f} | {'#' * c}" for i, c in enumerate(counts)]


def score_pairs(pairs: List[dict], embedder) -> List[dict]:
    docs = embedder.embed_documents([p["a"] for p in pairs])
    return [dict(p, similarity=round(cosine(d, embedder.embed_query(p["b"])), 4)) for p, d in zip(pairs, docs)]


def evaluate(scored_pairs: List[dict]) -> dict:
    tune = [(p["similarity"], p["label"] == "DUPLICATE") for p in scored_pairs if p["split"] == "tune"]
    held = [(p["similarity"], p["label"] == "DUPLICATE") for p in scored_pairs if p["split"] == "heldout"]
    threshold = choose_threshold(tune)
    return {
        "threshold": threshold,
        "tune": dict(rates(tune, threshold), pairs=len(tune)),
        "heldout": dict(rates(held, threshold), pairs=len(held)),
    }


def main():
    from Backend.config import EMBED_MODEL
    from Backend.storage.embedder import OllamaEmbedder

    data = json.loads(PAIRS_FILE.read_text(encoding="utf-8"))
    pairs = data["pairs"]
    print(f"Scoring {len(pairs)} labelled pairs with {EMBED_MODEL} via Ollama...")
    try:
        scored = score_pairs(pairs, OllamaEmbedder())
    except Exception as e:
        sys.exit(f"Could not reach Ollama ({e.__class__.__name__}: {e}). Start it with: docker compose up -d ollama")

    result = evaluate(scored)
    sims = [p["similarity"] for p in scored]
    lo, hi = min(sims), max(sims)
    for label in ("DUPLICATE", "DISTINCT"):
        values = [p["similarity"] for p in scored if p["split"] == "tune" and p["label"] == label]
        print(f"\nTuning half, {label} pairs (n={len(values)}):")
        print("\n".join(histogram(values, lo, hi)))

    t, held = result["threshold"], result["heldout"]
    print(f"\nChosen threshold (tuning half): {t}")
    print(f"Held-out half ({held['pairs']} pairs): suppression rate {held['suppression_rate']:.0%}, "
          f"false-suppression rate {held['false_suppression_rate']:.0%}")

    if data.get("labelled_by", [""])[0].startswith("DRAFT"):
        print("\nNote: novelty_pairs.json labels are still marked DRAFT. Have two team members confirm them.")

    RESULT_FILE.write_text(json.dumps({
        **result,
        "model": EMBED_MODEL,
        "evaluated_at": datetime.now(timezone.utc).isoformat(),
        "pairs": [{k: p[k] for k in ("id", "split", "label", "similarity")} for p in scored],
    }, indent=2), encoding="utf-8")
    print(f"Saved to {RESULT_FILE.relative_to(ROOT_DIR)}; the Telegram digest now uses threshold {t}.")


if __name__ == "__main__":
    main()
