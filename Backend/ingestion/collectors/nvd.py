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
        Fetches the newest CVEs from NVD 2.0.
        Retrieves CVEs published in the last `days_back` days (default 7 days)
        per Task 1.3 specification, newest first.

        NVD returns a date window oldest first, so taking the first page would
        give the CVEs published about `days_back` days ago. Instead a one-record
        request reads `totalResults`, then the last page of the window is fetched
        and reversed. Rejected records are skipped.
        """
        page_size = min(limit or 10, 50)
        base_params: Dict[str, Any] = {}
        if query_by_date:
            start_date, end_date = self._get_date_window(days_back)
            base_params["pubStartDate"] = start_date
            base_params["pubEndDate"] = end_date

        envelopes: List[StagingEnvelope] = []
        ingested_at = get_utc_now_iso()

        try:
            total = self._total_results(base_params)
            # Fetch a little more than needed so skipped (rejected) records don't leave the page short
            fetch_size = min(page_size * 2, 100)
            start_index = max(0, total - fetch_size)
            # NVD asks clients without an API key to wait about 6 s between requests
            time.sleep(1 if NVD_API_KEY else 6)
            data = self._fetch_page(base_params, start_index, fetch_size)
            vulnerabilities = data.get("vulnerabilities", [])

            def published(entry: Dict[str, Any]) -> str:
                return (entry.get("cve") or {}).get("published", "")

            for entry in sorted(vulnerabilities, key=published, reverse=True):
                cve = entry.get("cve", {})
                if str(cve.get("vulnStatus", "")).lower() == "rejected":
                    continue
                envelope = self._envelope_from_cve(cve, ingested_at)
                if envelope is None:
                    continue
                envelopes.append(envelope)

                if limit and len(envelopes) >= limit:
                    break

        except Exception as e:
            logger.error(f"Error collecting from NVD 2.0: {e}")

        logger.info(f"Successfully collected {len(envelopes)} items from NVD 2.0")
        return envelopes

    def _fetch_page(self, base_params: Dict[str, Any], start_index: int, results_per_page: int) -> Dict[str, Any]:
        params = dict(base_params, resultsPerPage=results_per_page, startIndex=start_index)
        req_url = f"{self.base_url}?{urllib.parse.urlencode(params)}"
        logger.info(f"Fetching CVEs from NVD 2.0: {req_url}")
        return json.loads(fetch_url(req_url, headers=self._get_headers(), timeout=20))

    def _total_results(self, base_params: Dict[str, Any]) -> int:
        """Number of CVEs in the window, read from a one-record request."""
        return int(self._fetch_page(base_params, 0, 1).get("totalResults", 0))

    def fetch_by_cve_id(self, cve_id: str) -> Optional[StagingEnvelope]:
        """Re-fetches one CVE record, used to check older items for updates."""
        req_url = f"{self.base_url}?{urllib.parse.urlencode({'cveId': cve_id})}"
        try:
            data = json.loads(fetch_url(req_url, headers=self._get_headers(), timeout=20))
            vulnerabilities = data.get("vulnerabilities", [])
            if not vulnerabilities:
                return None
            return self._envelope_from_cve(vulnerabilities[0].get("cve", {}), get_utc_now_iso())
        except Exception as e:
            logger.warning(f"Could not re-check {cve_id} on NVD: {e}")
            return None

    def _envelope_from_cve(self, cve: Dict[str, Any], ingested_at: str) -> Optional[StagingEnvelope]:
        cve_id = cve.get("id", "").strip().upper()
        if not cve_id:
            return None

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
        return envelope

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
