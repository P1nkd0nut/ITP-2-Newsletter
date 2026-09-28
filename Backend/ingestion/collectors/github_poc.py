"""
GitHub Proof-of-Concept (PoC) Detector.
Searches public GitHub repositories referencing ingested CVE IDs.
Captures basic reliability metadata: stars, repository age, author, and description.
"""
import json
import logging
from typing import List, Optional
import urllib.parse
from Backend.config import GITHUB_TOKEN
from Backend.ingestion.models import PoCReference, StagingEnvelope
from Backend.ingestion.utils import fetch_url

logger = logging.getLogger(__name__)


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
        params = {
            "q": query,
            "sort": "stars",
            "order": "desc",
            "per_page": limit,
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
                poc = PoCReference(
                    url=repo.get("html_url", ""),
                    stars=repo.get("stargazers_count", 0),
                    author=repo.get("owner", {}).get("login"),
                    created_at=repo.get("created_at"),
                    description=repo.get("description"),
                )
                pocs.append(poc)

        except Exception as e:
            logger.warning(f"Could not fetch GitHub PoCs for {cve_id}: {e}")

        return pocs

    def enrich_envelope_with_pocs(self, envelope: StagingEnvelope, limit: int = 3) -> StagingEnvelope:
        """Enriches an ingested StagingEnvelope with public PoC URLs and metadata if CVE_ID is present."""
        if envelope.CVE_ID and not envelope.PoC_URLs:
            pocs = self.find_pocs_for_cve(envelope.CVE_ID, limit=limit)
            if pocs:
                envelope.PoC_Details = pocs
                envelope.PoC_URLs = [p.url for p in pocs]
        return envelope
