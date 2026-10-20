"""
Change tracking between ingestion runs.

Compares a fresh batch of envelopes against the previous latest_envelopes.json
and labels each item NEW, UPDATED or UNCHANGED. Items that dropped out of the
feeds are carried over (until they age past the retention window) so the
dashboard keeps them. Only files in the repo are used, so it behaves the same
locally and in GitHub Actions.
"""
import difflib
import json
import logging
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from Backend.ingestion.models import StagingEnvelope

logger = logging.getLogger(__name__)

NEW = "NEW"
UPDATED = "UPDATED"
UNCHANGED = "UNCHANGED"

# Structured fields worth calling out when they change
TRACKED_FIELDS = {
    "Title": "title",
    "CVSS": "CVSS score",
    "CWE": "CWE",
    "KEV_Status": "CISA KEV status",
    "Vendor_Product": "affected product",
    "Affected_Versions": "affected versions",
}

_WORD_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]*")


def item_key(env: StagingEnvelope) -> str:
    """Item_ID is deterministic per source and already embeds the CVE ID (e.g. nvd-cve-2024-3400)."""
    return env.Item_ID or f"{env.Source_Type}:{env.CVE_ID}"


def load_previous(path: Path) -> List[StagingEnvelope]:
    if not path.exists():
        return []
    try:
        with open(path, "r", encoding="utf-8") as f:
            return [StagingEnvelope.model_validate(item) for item in json.load(f)]
    except Exception as e:
        logger.warning(f"Could not read previous envelopes from {path}: {e}")
        return []


def _word_diff(old: str, new: str, max_words: int = 12) -> Optional[str]:
    """Short summary of words added/removed between two raw texts."""
    old_words = _WORD_RE.findall(old or "")
    new_words = _WORD_RE.findall(new or "")
    added: List[str] = []
    removed: List[str] = []
    matcher = difflib.SequenceMatcher(a=old_words, b=new_words, autojunk=False)
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag in ("replace", "delete"):
            removed.extend(old_words[i1:i2])
        if tag in ("replace", "insert"):
            added.extend(new_words[j1:j2])
    if not added and not removed:
        return None
    parts = []
    if added:
        snippet = " ".join(added[:max_words]) + (" ..." if len(added) > max_words else "")
        parts.append(f"+{len(added)} words (\"{snippet}\")")
    if removed:
        snippet = " ".join(removed[:max_words]) + (" ..." if len(removed) > max_words else "")
        parts.append(f"-{len(removed)} words (\"{snippet}\")")
    return "Source text changed: " + "; ".join(parts)


def _normalise(value: Any) -> Any:
    """Order-insensitive form of list-like fields (feeds return them in varying order)."""
    if isinstance(value, list):
        return sorted(str(v) for v in value)
    if isinstance(value, str) and ", " in value:
        return sorted(part.strip() for part in value.split(","))
    return value


def describe_changes(old: StagingEnvelope, new: StagingEnvelope) -> List[str]:
    """Human-readable list of what differs between two versions of one item."""
    changes: List[str] = []
    for field, label in TRACKED_FIELDS.items():
        before, after = getattr(old, field), getattr(new, field)
        if _normalise(before) != _normalise(after):
            changes.append(f"{label}: {before if before not in (None, '') else 'none'} -> {after if after not in (None, '') else 'none'}")

    old_pocs, new_pocs = set(old.PoC_URLs or []), set(new.PoC_URLs or [])
    for url in sorted(new_pocs - old_pocs):
        changes.append(f"new PoC link: {url}")
    for url in sorted(old_pocs - new_pocs):
        changes.append(f"PoC link no longer found: {url}")

    if old.Content_Hash != new.Content_Hash:
        changes.append(_word_diff(old.Raw_Content, new.Raw_Content) or "Source text changed (formatting only)")
    return changes


def _carry_forward_pocs(old: StagingEnvelope, new: StagingEnvelope) -> None:
    """
    Keeps PoCs found on earlier runs. A rate-limited or skipped GitHub search
    returns nothing, which must not read as the PoC having disappeared.
    """
    known = set(new.PoC_URLs or [])
    kept = [url for url in (old.PoC_URLs or []) if url not in known]
    if not kept:
        return
    details = {d.url: d for d in (old.PoC_Details or [])}
    new.PoC_URLs = kept + (new.PoC_URLs or [])
    new.PoC_Details = [details[u] for u in kept if u in details] + (new.PoC_Details or [])


def _parse_ts(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        ts = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def apply_change_tracking(
    current: List[StagingEnvelope],
    previous: List[StagingEnvelope],
    retain_days: int = 30,
    now: Optional[datetime] = None,
) -> Tuple[List[StagingEnvelope], Dict[str, int]]:
    """
    Labels `current` against `previous` and appends previous items that were not
    fetched this run, dropping any not seen within `retain_days`.
    Returns (merged envelopes, counts per status).
    """
    now = now or datetime.now(timezone.utc)
    now_iso = now.isoformat()
    prev_by_key = {item_key(p): p for p in previous}
    counts = {NEW: 0, UPDATED: 0, UNCHANGED: 0, "CARRIED_OVER": 0, "EXPIRED": 0}

    merged: List[StagingEnvelope] = []
    seen_keys = set()
    for env in current:
        key = item_key(env)
        if key in seen_keys:
            continue
        seen_keys.add(key)
        old = prev_by_key.get(key)
        env.Last_Seen = now_iso
        if old is None:
            env.Change_Status = NEW
            env.Change_Summary = None
            env.First_Seen = now_iso
            env.Last_Changed = now_iso
        else:
            env.First_Seen = old.First_Seen or old.Ingested_At
            _carry_forward_pocs(old, env)
            changes = describe_changes(old, env)
            if changes:
                env.Change_Status = UPDATED
                env.Change_Summary = changes
                env.Last_Changed = now_iso
            else:
                env.Change_Status = UNCHANGED
                env.Change_Summary = None
                env.Last_Changed = old.Last_Changed or env.First_Seen
        counts[env.Change_Status] += 1
        merged.append(env)

    cutoff = now - timedelta(days=retain_days)
    for key, old in prev_by_key.items():
        if key in seen_keys:
            continue
        last_seen = _parse_ts(old.Last_Seen or old.Ingested_At)
        if last_seen and last_seen < cutoff:
            counts["EXPIRED"] += 1
            continue
        # Not in today's feed window; nothing new was observed about it
        old.Change_Status = UNCHANGED
        old.Change_Summary = None
        old.First_Seen = old.First_Seen or old.Ingested_At
        old.Last_Seen = old.Last_Seen or old.Ingested_At
        old.Last_Changed = old.Last_Changed or old.First_Seen
        counts["CARRIED_OVER"] += 1
        merged.append(old)

    return merged, counts
