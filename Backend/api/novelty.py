"""
Novelty check for the weekly digest.

Two rules keep the newsletter from repeating itself:
  1. Same flaw, several sources: items sharing a CVE ID (e.g. the NVD record,
     the CISA KEV entry and the GitHub advisory) are merged into the one with
     the highest priority.
  2. Already published: every item sent in a digest is recorded. It is only
     sent again when something new happened since: it was added to CISA KEV,
     a new public PoC appeared, or its CVSS score changed.

The record is a JSON ledger (published_ledger.json), mirrored into the Qdrant
'groundedcve_published' collection with an embedding of the card. Items with
no CVE ID (research write-ups) are also checked against that collection, so a
write-up that is nearly identical to one already sent is skipped.
"""
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from Backend.config import QDRANT_COLLECTION_PUBLISHED, STAGING_DIR

LEDGER_FILE = STAGING_DIR / "published_ledger.json"
DEFAULT_SIMILARITY = 0.92


def novelty_key(c: Dict[str, Any]) -> str:
    env = c.get("envelope") or {}
    return (env.get("CVE_ID") or "").upper() or env.get("Item_ID", "")


def fingerprint(c: Dict[str, Any]) -> Dict[str, Any]:
    """The facts whose change makes an already-sent item worth sending again."""
    env = c.get("envelope") or {}
    return {
        "kev": bool(env.get("KEV_Status")),
        "pocs": len(env.get("PoC_URLs") or []),
        "cvss": env.get("CVSS"),
    }


def whats_new(old: Dict[str, Any], new: Dict[str, Any]) -> List[str]:
    reasons = []
    if new["kev"] and not old.get("kev"):
        reasons.append("now actively exploited (CISA KEV)")
    if new["pocs"] > old.get("pocs", 0):
        reasons.append("new public PoC")
    if new["cvss"] is not None and new["cvss"] != old.get("cvss"):
        reasons.append(f"CVSS now {new['cvss']}")
    return reasons


def merge_same_flaw(items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Keep one item per CVE: the first one, so pass items sorted by priority.
    The kept item lists the other sources under 'also_reported_by'.
    """
    kept: Dict[str, Dict[str, Any]] = {}
    for c in items:
        key = novelty_key(c)
        if key not in kept:
            kept[key] = dict(c, also_reported_by=[])
        else:
            src = (c.get("envelope") or {}).get("Source_Type")
            if src and src not in kept[key]["also_reported_by"]:
                kept[key]["also_reported_by"].append(src)
    return list(kept.values())


def card_text(c: Dict[str, Any]) -> str:
    card = c.get("grounded_card") or {}
    title = (c.get("envelope") or {}).get("Title", "")
    return " ".join(x for x in (title, card.get("mechanism"), card.get("impact")) if x)


class PublishedIndex:
    """Published cards in Qdrant, used to catch near-identical write-ups without a CVE ID."""

    def __init__(self, client, embedder, collection: str = QDRANT_COLLECTION_PUBLISHED,
                 threshold: float = DEFAULT_SIMILARITY):
        from Backend.storage.init_qdrant import ensure_collection

        self.client = client
        self.embedder = embedder
        self.collection = collection
        self.threshold = threshold
        ensure_collection(client, collection)

    def add(self, c: Dict[str, Any], sent_at: str) -> None:
        from qdrant_client.models import PointStruct
        from Backend.storage.init_qdrant import DENSE_VECTOR_NAME

        key = novelty_key(c)
        env = c.get("envelope") or {}
        vec = self.embedder.embed_documents([card_text(c)])[0]
        self.client.upsert(self.collection, points=[PointStruct(
            id=str(uuid.uuid5(uuid.NAMESPACE_URL, f"groundedcve-published:{key}")),
            vector={DENSE_VECTOR_NAME: vec},
            payload={"key": key, "Item_ID": env.get("Item_ID"), "CVE_ID": env.get("CVE_ID"),
                     "Title": env.get("Title"), "sent_at": sent_at, **fingerprint(c)},
        )], wait=True)

    def near_duplicate(self, c: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        from Backend.storage.init_qdrant import DENSE_VECTOR_NAME

        hits = self.client.query_points(
            self.collection, query=self.embedder.embed_query(card_text(c)),
            using=DENSE_VECTOR_NAME, limit=1, with_payload=True,
        ).points
        if hits and hits[0].score >= self.threshold and hits[0].payload.get("key") != novelty_key(c):
            return dict(hits[0].payload, score=round(hits[0].score, 3))
        return None


class NoveltyChecker:
    def __init__(self, ledger_path: Path = LEDGER_FILE, index: Optional[PublishedIndex] = None):
        self.ledger_path = ledger_path
        self.index = index
        try:
            self.ledger: Dict[str, Dict[str, Any]] = json.loads(ledger_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            self.ledger = {}

    def assess(self, c: Dict[str, Any]) -> Dict[str, Any]:
        """status: NEW, UPDATE (sent before, something changed), SEEN or DUPLICATE (skip)."""
        key = novelty_key(c)
        prev = self.ledger.get(key)
        if prev:
            reasons = whats_new(prev.get("fingerprint", {}), fingerprint(c))
            return {"status": "UPDATE", "reasons": reasons} if reasons else {"status": "SEEN", "reasons": []}

        has_cve = bool((c.get("envelope") or {}).get("CVE_ID"))
        if self.index is not None and not has_cve:
            try:
                dup = self.index.near_duplicate(c)
            except Exception:
                dup = None  # Qdrant/Ollama hiccup: fall back to the ledger alone
            if dup:
                return {"status": "DUPLICATE", "reasons": [f"same as {dup.get('Title') or dup.get('key')}"],
                        "duplicate_of": dup.get("key")}
        return {"status": "NEW", "reasons": []}

    def filter(self, items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Items worth sending, each with a 'novelty' entry."""
        out = []
        for c in items:
            verdict = self.assess(c)
            if verdict["status"] in ("NEW", "UPDATE"):
                out.append(dict(c, novelty=verdict))
        return out

    def record(self, items: List[Dict[str, Any]], sent_at: Optional[str] = None) -> None:
        sent_at = sent_at or datetime.now(timezone.utc).isoformat()
        for c in items:
            env = c.get("envelope") or {}
            self.ledger[novelty_key(c)] = {
                "Item_ID": env.get("Item_ID"),
                "Title": env.get("Title"),
                "sent_at": sent_at,
                "fingerprint": fingerprint(c),
            }
            if self.index is not None:
                try:
                    self.index.add(c, sent_at)
                except Exception:
                    pass  # the ledger is the source of truth
        self.ledger_path.parent.mkdir(parents=True, exist_ok=True)
        self.ledger_path.write_text(json.dumps(self.ledger, indent=2, ensure_ascii=False), encoding="utf-8")
