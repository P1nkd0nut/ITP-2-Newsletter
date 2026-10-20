"""
GitHub Proof-of-Concept (PoC) Detector.
Searches public GitHub repositories referencing ingested CVE IDs.
Captures basic reliability metadata: stars, repository age, author, and description.
"""
import json
import logging
import re
from typing import List, Optional
import urllib.parse
from Backend.config import GITHUB_TOKEN
from Backend.ingestion.models import PoCReference, StagingEnvelope
from Backend.ingestion.utils import fetch_url

logger = logging.getLogger(__name__)


def mentions_cve(cve_id: str, text: Optional[str]) -> bool:
    """True if text names this exact CVE (CVE-2024-3400 does not match CVE-2024-34001)."""
    if not cve_id or not text:
        return False
    normalized = text.upper().replace("_", "-")
    return re.search(rf"(?<![0-9]){re.escape(cve_id.upper())}(?![0-9])", normalized) is not None


class GitHubPoCDetector:
    """Discovers public PoC repositories for CVEs via GitHub Search API."""

    def __init__(self, github_token: Optional[str] = None):
        self.github_token = github_token or GITHUB_TOKEN
        self.search_url = "https://api.github.com/search/repositories"

    def find_pocs_for_cve(self, cve_id: str, limit: int = 3) -> List[PoCReference]:
        """
        Searches GitHub for PoC repositories referencing the specified CVE ID.
        """
        if not cve_id or not cve_id.upper().startswith("CVE-"):
            return []

        query = f"{cve_id} poc"
        # Fetch extra results because generic tool repos are filtered out below
        params = {
            "q": query,
            "sort": "stars",
            "order": "desc",
            "per_page": max(limit * 5, 10),
        }
        encoded_query = urllib.parse.urlencode(params)
        req_url = f"{self.search_url}?{encoded_query}"

        headers = {"Accept": "application/vnd.github+json"}
        if self.github_token:
            headers["Authorization"] = f"Bearer {self.github_token}"

        pocs: List[PoCReference] = []
        try:
            raw_json = fetch_url(req_url, headers=headers, timeout=10)
            data = json.loads(raw_json)
            items = data.get("items", [])

            for repo in items:
                # Only keep repos that name this CVE, so broad tool repos
                # (nuclei-templates, metasploit-framework) are never listed as its PoC
                if mentions_cve(cve_id, repo.get("full_name")):
                    matched_on = "repo name"
                elif mentions_cve(cve_id, repo.get("description")):
                    matched_on = "repo description"
                else:
                    continue
                poc = PoCReference(
                    url=repo.get("html_url", ""),
                    stars=repo.get("stargazers_count", 0),
                    author=repo.get("owner", {}).get("login"),
                    created_at=repo.get("created_at"),
                    description=repo.get("description"),
                    source=f"GitHub repository search for '{query}'",
                    matched_on=matched_on,
                )
                pocs.append(poc)
                if len(pocs) >= limit:
                    break

        except Exception as e:
            logger.warning(f"Could not fetch GitHub PoCs for {cve_id}: {e}")

        return pocs

    def enrich_envelope_with_pocs(self, envelope: StagingEnvelope, limit: int = 3) -> StagingEnvelope:
        """Enriches an ingested StagingEnvelope with public PoC URLs and metadata if CVE_ID is present."""
        if not envelope.CVE_ID:
            return envelope
        # Merge with PoCs the source already listed (e.g. NVD 'Exploit' references)
        existing = set(envelope.PoC_URLs or [])
        new_pocs = [p for p in self.find_pocs_for_cve(envelope.CVE_ID, limit=limit) if p.url not in existing]
        if new_pocs:
            envelope.PoC_Details = (envelope.PoC_Details or []) + new_pocs
            envelope.PoC_URLs = (envelope.PoC_URLs or []) + [p.url for p in new_pocs]
        return envelope
