"""
GitHub Advisory Database Collector.
Monitors web and backend package ecosystems: npm, PyPI (pip), Go, and Maven.
"""
import json
import logging
from typing import List, Optional
from Backend.config import GITHUB_ADVISORIES_URL, GITHUB_TOKEN, WEB_ECOSYSTEMS
from Backend.ingestion.collectors.base import BaseCollector
from Backend.ingestion.models import StagingEnvelope, SourceType
from Backend.ingestion.utils import (
    compute_content_hash,
    fetch_url,
    get_utc_now_iso,
    normalize_to_iso,
)

logger = logging.getLogger(__name__)


class GitHubAdvisoryCollector(BaseCollector):
    """Collector for GitHub Security Advisory Database across web package ecosystems."""

    def __init__(self, ecosystems: Optional[List[str]] = None):
        super().__init__(name="GitHub Advisory Database", source_type=SourceType.GITHUB_ADVISORY)
        self.ecosystems = ecosystems or WEB_ECOSYSTEMS

    def collect(self, limit: Optional[int] = None) -> List[StagingEnvelope]:
        envelopes: List[StagingEnvelope] = []
        ingested_at = get_utc_now_iso()
        headers = {"Accept": "application/vnd.github+json"}
        if GITHUB_TOKEN:
            headers["Authorization"] = f"Bearer {GITHUB_TOKEN}"

        # Allocate per-ecosystem limit
        per_eco_limit = max(1, (limit // len(self.ecosystems)) if limit else 5)

        for eco in self.ecosystems:
            url = f"{GITHUB_ADVISORIES_URL}?ecosystem={eco}&sort=published&direction=desc&per_page={per_eco_limit}"
            logger.info(f"Querying GitHub Advisory Database for ecosystem: {eco}")
            try:
                raw_json = fetch_url(url, headers=headers)
                items = json.loads(raw_json)
                if not isinstance(items, list):
                    logger.warning(f"Unexpected response format for {eco}: {items}")
                    continue

                for item in items:
                    ghsa_id = item.get("ghsa_id", "")
                    cve_id = item.get("cve_id")
                    summary = item.get("summary") or "GitHub Security Advisory"
                    html_url = item.get("html_url") or f"https://github.com/advisories/{ghsa_id}"
                    published_at = item.get("published_at")
                    description = item.get("description") or summary

                    # Extract affected package names and vulnerable ranges
                    vulns = item.get("vulnerabilities", []) or []
                    packages = []
                    ranges = []
                    for v in vulns:
                        pkg_info = v.get("package", {}) or {}
                        pkg_name = pkg_info.get("name")
                        if pkg_name:
                            packages.append(f"{eco}:{pkg_name}")
                        v_range = v.get("vulnerable_version_range")
                        if v_range:
                            ranges.append(v_range)

                    vendor_product = ", ".join(list(set(packages))) if packages else None
                    affected_versions = list(set(ranges)) if ranges else None

                    # Extract CVSS
                    cvss_data = item.get("cvss") or {}
                    cvss_score = cvss_data.get("score")
                    
                    # Extract CWEs
                    cwes = []
                    for c in item.get("cwes", []):
                        if isinstance(c, str):
                            cwes.append(c)
                        elif isinstance(c, dict) and c.get("cwe_id"):
                            cwes.append(c.get("cwe_id"))

                    # Extract references safely
                    refs = []
                    for ref in item.get("references", []):
                        if isinstance(ref, str):
                            refs.append(ref)
                        elif isinstance(ref, dict) and ref.get("url"):
                            refs.append(ref.get("url"))

                    envelope = StagingEnvelope(
                        Item_ID=f"ghsa-{ghsa_id.lower()}",
                        Source_Type=self.source_type,
                        Title=f"[{eco.upper()}] {summary}",
                        Source_URL=html_url,
                        Published_Date=normalize_to_iso(published_at),
                        Ingested_At=ingested_at,
                        Content_Hash=compute_content_hash(description),
                        Raw_Content=description,
                        CVE_ID=cve_id,
                        Vendor_Product=vendor_product,
                        Affected_Versions=affected_versions,
                        CVSS=float(cvss_score) if cvss_score is not None else None,
                        CVSS_Version="3.1" if cvss_score else None,
                        CWE=cwes if cwes else None,
                        Extra_Metadata={
                            "ghsa_id": ghsa_id,
                            "severity": item.get("severity"),
                            "ecosystem": eco,
                            "references": refs,
                        },
                    )
                    envelopes.append(envelope)

            except Exception as e:
                logger.error(f"Failed to collect GitHub Advisories for ecosystem {eco}: {e}")

        if limit is not None and limit > 0:
            envelopes = envelopes[:limit]

        logger.info(f"Successfully collected {len(envelopes)} items from GitHub Advisories")
        return envelopes
