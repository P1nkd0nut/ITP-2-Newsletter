"""
Age-based re-check policy.

Newly published CVEs change often (NVD enrichment, new PoCs), so they are checked
every run. Older ones are checked less and less often, and anything published
more than a year ago is frozen: it is kept, but no longer updated.
"""
from datetime import datetime, timezone
from typing import Optional

FREEZE_AFTER_DAYS = 365

# (item is younger than this many days, re-check at most once per this many days)
RECHECK_TIERS = [
    (30, 1),    # first month: every daily run
    (180, 30),  # 1-6 months: monthly
    (365, 90),  # 6-12 months: quarterly
]

FREEZE_NOTICE = (
    "Published over a year ago. PoCs and details for older CVEs are no longer "
    "updated, so check the source for newer information."
)


def parse_ts(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        ts = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)


def age_days(published: Optional[str], now: Optional[datetime] = None) -> Optional[int]:
    ts = parse_ts(published)
    if ts is None:
        return None
    return max(0, ((now or datetime.now(timezone.utc)) - ts).days)


def is_frozen(published: Optional[str], now: Optional[datetime] = None) -> bool:
    age = age_days(published, now)
    return age is not None and age > FREEZE_AFTER_DAYS


def recheck_interval_days(published: Optional[str], now: Optional[datetime] = None) -> Optional[int]:
    """Minimum days between checks, or None when the item is frozen."""
    age = age_days(published, now)
    if age is None:
        return RECHECK_TIERS[0][1]
    for max_age, interval in RECHECK_TIERS:
        if age <= max_age:
            return interval
    return None


def is_due(published: Optional[str], last_checked: Optional[str], now: Optional[datetime] = None) -> bool:
    """True if the item is not frozen and its tier's interval has passed since the last check."""
    now = now or datetime.now(timezone.utc)
    interval = recheck_interval_days(published, now)
    if interval is None:
        return False
    checked = parse_ts(last_checked)
    return checked is None or (now - checked).total_seconds() >= interval * 86400 - 3600


def recency_label(published: Optional[str], now: Optional[datetime] = None) -> str:
    """Date-free description of how old an item is, for display."""
    age = age_days(published, now)
    if age is None:
        return "Monitored"
    if age <= 7:
        return "Recent"
    if age <= 30:
        return "Past month"
    if age <= 90:
        return "Past 3 months"
    if age <= 180:
        return "Past 6 months"
    if age <= 365:
        return "Past year"
    return "Over a year ago"
