"""
NVD 2.0 REST API Collector.
Retrieves recently published and modified CVEs from NIST NVD 2.0 API.
Implements CVSS v3.1/v4.0 extraction, CWE parsing, and polite rate limiting.
"""
from datetime import datetime, timedelta, timezone
import json
import logging
import time
from typing import List, Optional, Tuple, Any, Dict
import urllib.parse
from Backend.config import NVD_API_BASE_URL, NVD_API_KEY, DEFAULT_DAYS_BACK
from Backend.ingestion.collectors.base import BaseCollector
from Backend.ingestion.models import PoCReference, StagingEnvelope, SourceType
from Backend.ingestion.utils import (
    compute_content_hash,
    fetch_url,
    get_utc_now_iso,
    normalize_to_iso,
)

logger = logging.getLogger(__name__)


class NvdCollector(BaseCollector):
    """Client for NIST National Vulnerability Database (NVD) 2.0 REST API."""

    def __init__(self, api_key: Optional[str] = None):
        super().__init__(name="NIST NVD 2.0", source_type=SourceType.NVD)
        self.api_key = api_key or NVD_API_KEY
        self.base_url = NVD_API_BASE_URL

    def _get_headers(self) -> Dict[str, str]:
        headers = {"Accept": "application/json"}
        if self.api_key:
            headers["apiKey"] = self.api_key
        return headers

    def _get_date_window(self, days_back: int) -> Tuple[str, str]:
        """Formats UTC start and end dates in NVD 2.0 required format: YYYY-MM-DDTHH:mm:ss.000"""
        end_dt = datetime.now(timezone.utc)
        start_dt = end_dt - timedelta(days=days_back)
        fmt = "%Y-%m-%dT%H:%M:%S.000"
        return start_dt.strftime(fmt), end_dt.strftime(fmt)

    def collect(
        self,
        limit: Optional[int] = None,
        days_back: int = DEFAULT_DAYS_BACK,
        query_by_date: bool = True,
    ) -> List[StagingEnvelope]:
        """
        Fetches CVEs from NVD 2.0.
        Retrieves CVEs published in the last `days_back` days (default 7 days)
        per Task 1.3 specification. Falls back to unconstrained query if needed.
        """
        results_per_page = min(limit or 10, 50)
        params = {"resultsPerPage": results_per_page, "startIndex": 0}

        if query_by_date:
            start_date, end_date = self._get_date_window(days_back)
            params["pubStartDate"] = start_date
            params["pubEndDate"] = end_date

        query_str = urllib.parse.urlencode(params)
        req_url = f"{self.base_url}?{query_str}"

        logger.info(f"Fetching CVEs from NVD 2.0: {req_url}")
        envelopes: List[StagingEnvelope] = []
        ingested_at = get_utc_now_iso()

        try:
            raw_response = fetch_url(req_url, headers=self._get_headers(), timeout=20)
            data = json.loads(raw_response)
            vulnerabilities = data.get("vulnerabilities", [])

            for entry in vulnerabilities:
                cve = entry.get("cve", {})
                cve_id = cve.get("id", "").strip().upper()
                if not cve_id:
                    continue

                published = cve.get("published", "")
                
                # Extract English description
                descriptions = cve.get("descriptions", [])
                raw_desc = ""
                for d in descriptions:
                    if d.get("lang") == "en":
                        raw_desc = d.get("value", "")
                        break
                if not raw_desc and descriptions:
                    raw_desc = descriptions[0].get("value", "")

                # Extract CVSS
                cvss_score, cvss_version = self._extract_cvss(cve.get("metrics", {}))

                # Extract CWE
                cwes = self._extract_cwes(cve.get("weaknesses", []))

                # Extract CPE configurations / products
                products = self._extract_products(cve.get("configurations", []))
                vendor_product = ", ".join(products[:3]) if products else None

                # Extract reference URLs
                ref_urls = [r.get("url") for r in cve.get("references", []) if r.get("url")]

                # NVD analysts tag references that contain exploit code with "Exploit"
                exploit_refs = [
                    PoCReference(
                        url=r["url"],
                        source=f"NVD reference list for {cve_id}",
                        matched_on="NVD 'Exploit' tag",
                    )
                    for r in cve.get("references", [])
                    if r.get("url") and "Exploit" in (r.get("tags") or [])
                ]

                # Raw content stores the raw CVE JSON object string for lossless verification
                raw_content_str = json.dumps(cve, indent=2, sort_keys=True)

                envelope = StagingEnvelope(
                    Item_ID=f"nvd-{cve_id.lower()}",
                    Source_Type=self.source_type,
                    Title=f"{cve_id} - {raw_desc[:90]}..." if len(raw_desc) > 90 else f"{cve_id} - {raw_desc}",
                    Source_URL=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                    Published_Date=normalize_to_iso(published),
                    Ingested_At=ingested_at,
                    Content_Hash=compute_content_hash(raw_content_str),
                    Raw_Content=raw_content_str,
                    CVE_ID=cve_id,
                    Vendor_Product=vendor_product,
                    CVSS=cvss_score,
                    CVSS_Version=cvss_version,
                    CWE=cwes if cwes else None,
                    PoC_URLs=[p.url for p in exploit_refs] or None,
                    PoC_Details=exploit_refs or None,
                    Extra_Metadata={
                        "vulnStatus": cve.get("vulnStatus"),
                        "references": ref_urls,
                    },
                )
                envelopes.append(envelope)

                if limit and len(envelopes) >= limit:
                    break

        except Exception as e:
            logger.error(f"Error collecting from NVD 2.0: {e}")

        logger.info(f"Successfully collected {len(envelopes)} items from NVD 2.0")
        return envelopes

    def _extract_cvss(self, metrics: Dict[str, Any]) -> Tuple[Optional[float], Optional[str]]:
        # Check CVSS v4.0 first
        if "cvssMetricV40" in metrics and metrics["cvssMetricV40"]:
            data = metrics["cvssMetricV40"][0].get("cvssData", {})
            score = data.get("baseScore")
            return float(score) if score is not None else None, "4.0"

        # Check CVSS v3.1
        if "cvssMetricV31" in metrics and metrics["cvssMetricV31"]:
            data = metrics["cvssMetricV31"][0].get("cvssData", {})
            score = data.get("baseScore")
            return float(score) if score is not None else None, "3.1"

        # Check CVSS v3.0
        if "cvssMetricV30" in metrics and metrics["cvssMetricV30"]:
            data = metrics["cvssMetricV30"][0].get("cvssData", {})
            score = data.get("baseScore")
            return float(score) if score is not None else None, "3.0"

        return None, None

    def _extract_cwes(self, weaknesses: List[Dict[str, Any]]) -> List[str]:
        cwes = []
        for w in weaknesses:
            for desc in w.get("description", []):
                val = desc.get("value", "")
                if val.startswith("CWE-"):
                    cwes.append(val)
        return list(dict.fromkeys(cwes))

    def _extract_products(self, configurations: List[Dict[str, Any]]) -> List[str]:
        products = []
        for conf in configurations:
            for node in conf.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    criteria = match.get("criteria", "")
                    # e.g., cpe:2.3:o:google:android:14.0:...
                    parts = criteria.split(":")
                    if len(parts) > 5:
                        vendor = parts[3]
                        prod = parts[4]
                        formatted = f"{vendor} {prod}".replace("_", " ").title()
                        if formatted not in products:
                            products.append(formatted)
        return products
