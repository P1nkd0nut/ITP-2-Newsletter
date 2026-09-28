"""
CISA Known Exploited Vulnerabilities (KEV) Catalog Collector.
Fetches actively exploited CVEs from CISA's official feed.
"""
import json
import logging
from typing import List, Optional
from Backend.config import CISA_KEV_URL
from Backend.ingestion.collectors.base import BaseCollector
from Backend.ingestion.models import StagingEnvelope, SourceType
from Backend.ingestion.utils import (
    compute_content_hash,
    fetch_url,
    get_utc_now_iso,
    normalize_to_iso,
)

logger = logging.getLogger(__name__)


class CisaKevCollector(BaseCollector):
    """Collector for CISA Known Exploited Vulnerabilities (KEV) Catalog."""

    def __init__(self, catalog_url: str = CISA_KEV_URL):
        super().__init__(name="CISA KEV", source_type=SourceType.CISA_KEV)
        self.catalog_url = catalog_url

    def collect(self, limit: Optional[int] = None) -> List[StagingEnvelope]:
        logger.info(f"Fetching CISA KEV catalog from {self.catalog_url}")
        raw_text = fetch_url(self.catalog_url)
        data = json.loads(raw_text)

        vulnerabilities = data.get("vulnerabilities", [])
        # Sort by dateAdded descending to ensure the most recently added CVEs come first
        vulnerabilities_sorted = sorted(
            vulnerabilities,
            key=lambda x: x.get("dateAdded", ""),
            reverse=True,
        )

        if limit is not None and limit > 0:
            vulnerabilities_sorted = vulnerabilities_sorted[:limit]

        envelopes: List[StagingEnvelope] = []
        ingested_at = get_utc_now_iso()

        for item in vulnerabilities_sorted:
            cve_id = item.get("cveID", "").strip().upper()
            vendor = item.get("vendorProject", "").strip()
            product = item.get("product", "").strip()
            vuln_name = item.get("vulnerabilityName", "").strip()
            date_added = item.get("dateAdded", "")
            raw_item_json = json.dumps(item, indent=2, sort_keys=True)

            vendor_product = f"{vendor} {product}".strip() if vendor or product else None
            title = f"{cve_id} - {vuln_name}" if vuln_name else cve_id

            envelope = StagingEnvelope(
                Item_ID=f"cisa-kev-{cve_id.lower()}",
                Source_Type=self.source_type,
                Title=title,
                Source_URL=f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext={cve_id}",
                Published_Date=normalize_to_iso(date_added),
                Ingested_At=ingested_at,
                Content_Hash=compute_content_hash(raw_item_json),
                Raw_Content=raw_item_json,
                CVE_ID=cve_id,
                Vendor_Product=vendor_product,
                KEV_Status=True,
                Extra_Metadata={
                    "shortDescription": item.get("shortDescription"),
                    "requiredAction": item.get("requiredAction"),
                    "dueDate": item.get("dueDate"),
                    "knownRansomwareCampaignUse": item.get("knownRansomwareCampaignUse"),
                    "notes": item.get("notes"),
                },
            )
            envelopes.append(envelope)

        logger.info(f"Successfully collected {len(envelopes)} items from CISA KEV")
        return envelopes
