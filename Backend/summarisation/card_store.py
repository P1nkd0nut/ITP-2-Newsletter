"""
Storage for gate-checked cards.

grounded_cards.json holds PASSED cards only; it is what the dashboard digest
and the Telegram digest read. Quarantined and failed cards are appended to
quarantine_log.jsonl with the gate's reasons and are never published.
"""
import json
from pathlib import Path
from typing import Any, Dict, Iterable

from Backend.config import GROUNDED_CARDS_FILE, QUARANTINE_LOG_FILE


def load_cards(path: Path = GROUNDED_CARDS_FILE) -> Dict[str, Dict[str, Any]]:
    """Passed cards keyed by Item_ID."""
    if not path.exists():
        return {}
    try:
        records = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return {r["Item_ID"]: r for r in records if r.get("status") == "PASSED" and r.get("card")}


def save_cards(cards: Dict[str, Dict[str, Any]], path: Path = GROUNDED_CARDS_FILE) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    passed = [r for r in cards.values() if r.get("status") == "PASSED"]
    path.write_text(json.dumps(passed, indent=2, ensure_ascii=False), encoding="utf-8")


def log_rejected(records: Iterable[Dict[str, Any]], path: Path = QUARANTINE_LOG_FILE) -> int:
    """Append quarantined/errored card records, one JSON object per line."""
    path.parent.mkdir(parents=True, exist_ok=True)
    n = 0
    with open(path, "a", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
            n += 1
    return n
