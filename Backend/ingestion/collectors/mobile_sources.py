"""
Mobile Threat Intelligence Collectors.
Target sources:
- Frida Dynamic Instrumentation Releases & Changelogs (hooking/bypasses)
- Android Open Source Project (AOSP) Security Bulletins
- Apple Security Releases (iOS/iPadOS/macOS)
"""
import hashlib
import json
import logging
import re
from typing import List, Optional
from Backend.config import (
    FRIDA_RELEASES_URL,
    ANDROID_BULLETIN_INDEX_URL,
    APPLE_SECURITY_RELEASES_URL,
    GITHUB_TOKEN,
)
from Backend.ingestion.collectors.base import BaseCollector
from Backend.ingestion.models import StagingEnvelope, SourceType
from Backend.ingestion.utils import (
    compute_content_hash,
    fetch_url,
    get_utc_now_iso,
    normalize_to_iso,
)

logger = logging.getLogger(__name__)


class FridaCollector(BaseCollector):
    """Collects Frida dynamic instrumentation releases and hooking tradecraft notes."""

    def __init__(self):
        super().__init__(name="Frida Releases", source_type=SourceType.FRIDA)

    def collect(self, limit: Optional[int] = None) -> List[StagingEnvelope]:
        logger.info(f"Fetching Frida releases from {FRIDA_RELEASES_URL}")
        headers = {"Accept": "application/vnd.github+json"}
        if GITHUB_TOKEN:
            headers["Authorization"] = f"Bearer {GITHUB_TOKEN}"

        envelopes: List[StagingEnvelope] = []
        ingested_at = get_utc_now_iso()

        try:
            raw_json = fetch_url(FRIDA_RELEASES_URL, headers=headers)
            releases = json.loads(raw_json)
            if not isinstance(releases, list):
                logger.warning(f"Unexpected response from Frida releases: {releases}")
                return []

            if limit is not None and limit > 0:
                releases = releases[:limit]

            for rel in releases:
                tag = rel.get("tag_name", "")
                name = rel.get("name") or f"Frida {tag}"
                body = rel.get("body") or f"Frida instrumentation release {tag}"
                html_url = rel.get("html_url", f"https://github.com/frida/frida/releases/tag/{tag}")
                published_at = rel.get("published_at")

                envelope = StagingEnvelope(
                    Item_ID=f"frida-{tag.replace('.', '-')}",
                    Source_Type=self.source_type,
                    Title=f"[Dynamic Instrumentation] {name}",
                    Source_URL=html_url,
                    Published_Date=normalize_to_iso(published_at),
                    Ingested_At=ingested_at,
                    Content_Hash=compute_content_hash(body),
                    Raw_Content=body,
                    Vendor_Product="Frida Instrumentation Framework",
                    Extra_Metadata={
                        "tag_name": tag,
                        "prerelease": rel.get("prerelease", False),
                    },
                )
                envelopes.append(envelope)

        except Exception as e:
            logger.error(f"Error collecting Frida releases: {e}")

        logger.info(f"Successfully collected {len(envelopes)} items from Frida releases")
        return envelopes


class AndroidBulletinCollector(BaseCollector):
    """Collects recent Android Open Source Project Security Bulletins."""

    def __init__(self):
        super().__init__(name="Android Security Bulletins", source_type=SourceType.ANDROID_BULLETIN)

    def collect(self, limit: Optional[int] = None) -> List[StagingEnvelope]:
        logger.info(f"Fetching Android security bulletin index from {ANDROID_BULLETIN_INDEX_URL}")
        envelopes: List[StagingEnvelope] = []
        ingested_at = get_utc_now_iso()

        try:
            html = fetch_url(ANDROID_BULLETIN_INDEX_URL)
            # Find bulletin links, e.g., /docs/security/bulletin/2024-08-01
            pattern = r'href=["\'](/docs/security/bulletin/(\d{4}-\d{2}-\d{2}))["\']'
            matches = re.findall(pattern, html)
            seen = set()
            bulletins = []
            for path, date_str in matches:
                if date_str not in seen:
                    seen.add(date_str)
                    bulletins.append((path, date_str))

            if limit is not None and limit > 0:
                bulletins = bulletins[:limit]

            for path, date_str in bulletins:
                full_url = f"https://source.android.com{path}"
                bulletin_html = fetch_url(full_url)
                title = f"Android Security Bulletin - {date_str}"
                item_id = f"aosp-bulletin-{date_str}"

                envelope = StagingEnvelope(
                    Item_ID=item_id,
                    Source_Type=self.source_type,
                    Title=title,
                    Source_URL=full_url,
                    Published_Date=normalize_to_iso(date_str),
                    Ingested_At=ingested_at,
                    Content_Hash=compute_content_hash(bulletin_html),
                    Raw_Content=bulletin_html,
                    Vendor_Product="Google Android (AOSP)",
                )
                envelopes.append(envelope)

        except Exception as e:
            logger.error(f"Error collecting Android bulletins: {e}")

        logger.info(f"Successfully collected {len(envelopes)} items from Android bulletins")
        return envelopes


class AppleSecurityCollector(BaseCollector):
    """Collects Apple Security Release disclosures."""

    def __init__(self):
        super().__init__(name="Apple Security Releases", source_type=SourceType.APPLE_SECURITY)

    def collect(self, limit: Optional[int] = None) -> List[StagingEnvelope]:
        logger.info(f"Fetching Apple Security Releases from {APPLE_SECURITY_RELEASES_URL}")
        envelopes: List[StagingEnvelope] = []
        ingested_at = get_utc_now_iso()

        try:
            raw_html = fetch_url(APPLE_SECURITY_RELEASES_URL)
            # Match release rows or sections mentioning iOS, iPadOS, macOS
            # Save raw HTML disclosure page as staging envelope
            envelope = StagingEnvelope(
                Item_ID="apple-security-releases-index",
                Source_Type=self.source_type,
                Title="Apple Security Releases (iOS, iPadOS, macOS, Safari)",
                Source_URL=APPLE_SECURITY_RELEASES_URL,
                Published_Date=ingested_at,
                Ingested_At=ingested_at,
                Content_Hash=compute_content_hash(raw_html),
                Raw_Content=raw_html,
                Vendor_Product="Apple iOS / iPadOS / macOS",
            )
            envelopes.append(envelope)
        except Exception as e:
            logger.error(f"Error collecting Apple Security releases: {e}")

        return envelopes
