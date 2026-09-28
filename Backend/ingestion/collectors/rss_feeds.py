"""
RSS / Atom feed collectors for specialized offensive research write-ups.
Target sources:
- PortSwigger Web Security Research (Web Application Tradecraft)
- Google Project Zero (Mobile / Deep Technical Vulnerabilities)
"""
import hashlib
import logging
from typing import List, Optional
import feedparser
from Backend.config import PORTSWIGGER_RSS_URL, PROJECT_ZERO_RSS_URL
from Backend.ingestion.collectors.base import BaseCollector
from Backend.ingestion.models import StagingEnvelope, SourceType
from Backend.ingestion.utils import (
    compute_content_hash,
    get_utc_now_iso,
    normalize_to_iso,
)

logger = logging.getLogger(__name__)


class RSSFeedCollector(BaseCollector):
    """Generic RSS / Atom feed collector using feedparser."""

    def __init__(self, name: str, source_type: SourceType, feed_url: str):
        super().__init__(name=name, source_type=source_type)
        self.feed_url = feed_url

    def collect(self, limit: Optional[int] = None) -> List[StagingEnvelope]:
        logger.info(f"Parsing feed '{self.name}' from {self.feed_url}")
        feed = feedparser.parse(self.feed_url)

        if feed.bozo and not feed.entries:
            logger.warning(f"Failed or ill-formed feed for {self.name}: {feed.bozo_exception}")
            return []

        entries = feed.entries
        if limit is not None and limit > 0:
            entries = entries[:limit]

        envelopes: List[StagingEnvelope] = []
        ingested_at = get_utc_now_iso()

        for entry in entries:
            title = getattr(entry, "title", "Untitled Research Post").strip()
            link = getattr(entry, "link", self.feed_url).strip()

            # Date parsing
            pub_date = getattr(entry, "published_parsed", None) or getattr(entry, "updated_parsed", None)
            pub_iso = normalize_to_iso(pub_date) if pub_date else normalize_to_iso(getattr(entry, "published", None))

            # Raw content retrieval
            raw_body = ""
            if hasattr(entry, "content") and entry.content:
                raw_body = entry.content[0].get("value", "")
            elif hasattr(entry, "summary"):
                raw_body = entry.summary or ""
            else:
                raw_body = title

            # Generate stable deterministic ID
            item_slug = hashlib.sha1(link.encode("utf-8")).hexdigest()[:12]
            item_id = f"{self.source_type.value.lower()}-{item_slug}"

            envelope = StagingEnvelope(
                Item_ID=item_id,
                Source_Type=self.source_type,
                Title=title,
                Source_URL=link,
                Published_Date=pub_iso,
                Ingested_At=ingested_at,
                Content_Hash=compute_content_hash(raw_body),
                Raw_Content=raw_body,
                Extra_Metadata={
                    "author": getattr(entry, "author", None),
                    "tags": [tag.term for tag in getattr(entry, "tags", [])] if hasattr(entry, "tags") else [],
                },
            )
            envelopes.append(envelope)

        logger.info(f"Successfully collected {len(envelopes)} items from {self.name}")
        return envelopes


def create_portswigger_collector() -> RSSFeedCollector:
    return RSSFeedCollector(
        name="PortSwigger Web Security Research",
        source_type=SourceType.PORTSWIGGER,
        feed_url=PORTSWIGGER_RSS_URL,
    )


def create_project_zero_collector() -> RSSFeedCollector:
    return RSSFeedCollector(
        name="Google Project Zero Research",
        source_type=SourceType.PROJECT_ZERO,
        feed_url=PROJECT_ZERO_RSS_URL,
    )
