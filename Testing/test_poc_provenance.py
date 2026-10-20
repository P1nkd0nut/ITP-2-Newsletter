"""
Tests that PoC links are CVE-specific and that every reference says where it came from.
"""
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from Backend.api.data_service import DataService, describe_poc
from Backend.ingestion.collectors.github_poc import GitHubPoCDetector, mentions_cve
from Backend.ingestion.models import PoCReference, SourceType, StagingEnvelope


def _search_response(*repos):
    return json.dumps({"items": [
        {
            "html_url": f"https://github.com/{name}",
            "full_name": name,
            "description": desc,
            "stargazers_count": stars,
            "owner": {"login": name.split("/")[0]},
        }
        for name, desc, stars in repos
    ]})


class TestCveMatching(unittest.TestCase):
    def test_exact_id_only(self):
        self.assertTrue(mentions_cve("CVE-2024-3400", "h4x0r/CVE-2024-3400-poc"))
        self.assertTrue(mentions_cve("CVE-2024-3400", "exploit for cve_2024_3400"))
        self.assertFalse(mentions_cve("CVE-2024-3400", "PoC for CVE-2024-34001"))
        self.assertFalse(mentions_cve("CVE-2024-3400", "projectdiscovery/nuclei-templates"))


class TestGitHubPoCFilter(unittest.TestCase):
    @patch("Backend.ingestion.collectors.github_poc.fetch_url")
    def test_generic_repos_are_dropped(self, mock_fetch):
        mock_fetch.return_value = _search_response(
            ("projectdiscovery/nuclei-templates", "Community curated templates", 20000),
            ("rapid7/metasploit-framework", "Metasploit Framework", 30000),
            ("someone/CVE-2024-3400", "GlobalProtect RCE", 150),
            ("other/panos-rce", "Exploit for CVE-2024-3400", 40),
        )
        pocs = GitHubPoCDetector(github_token="x").find_pocs_for_cve("CVE-2024-3400", limit=3)
        self.assertEqual([p.url for p in pocs], [
            "https://github.com/someone/CVE-2024-3400",
            "https://github.com/other/panos-rce",
        ])
        self.assertEqual(pocs[0].matched_on, "repo name")
        self.assertEqual(pocs[1].matched_on, "repo description")
        self.assertIn("GitHub repository search", pocs[0].source)

    @patch("Backend.ingestion.collectors.github_poc.fetch_url")
    def test_enrich_merges_with_existing_pocs(self, mock_fetch):
        mock_fetch.return_value = _search_response(("someone/CVE-2024-3400", "", 5))
        nvd_ref = PoCReference(url="https://example.com/exploit", source="NVD reference list", matched_on="NVD 'Exploit' tag")
        env = StagingEnvelope(
            Item_ID="nvd-cve-2024-3400", Source_Type=SourceType.NVD, Title="t", Source_URL="u",
            Published_Date="2024-04-12T00:00:00Z", Ingested_At="2024-04-12T00:00:00Z",
            Content_Hash="h", Raw_Content="r", CVE_ID="CVE-2024-3400",
            PoC_URLs=[nvd_ref.url], PoC_Details=[nvd_ref],
        )
        GitHubPoCDetector(github_token="x").enrich_envelope_with_pocs(env, limit=2)
        self.assertEqual(env.PoC_URLs, ["https://example.com/exploit", "https://github.com/someone/CVE-2024-3400"])
        self.assertEqual(len(env.PoC_Details), 2)


class TestPoCProvenance(unittest.TestCase):
    def test_fetched_poc_names_its_source(self):
        label = describe_poc("https://github.com/someone/CVE-2024-3400", "CVE-2024-3400", {
            "url": "https://github.com/someone/CVE-2024-3400",
            "source": "GitHub repository search for 'CVE-2024-3400 poc'",
            "matched_on": "repo name",
            "stars": 150,
        })
        self.assertEqual(label["type"], "PoC / Weaponized Exploit")
        self.assertIn("matched in repo name", label["found_via"])
        self.assertIn("150 stars", label["found_via"])

    def test_generic_seed_repo_is_labelled(self):
        label = describe_poc("https://github.com/rapid7/metasploit-framework", "CVE-2026-102510", None)
        self.assertIn("Not CVE-Specific", label["type"])

    def test_dashboard_references_carry_found_via(self):
        # Self-contained candidate so the test does not depend on whatever the last ingestion fetched
        cve = "CVE-2024-3400"
        candidate = {
            "envelope": {
                "Item_ID": "nvd-cve-2024-3400", "Source_Type": "NVD", "Title": "PAN-OS GlobalProtect command injection",
                "Source_URL": "https://nvd.nist.gov/vuln/detail/CVE-2024-3400",
                "Published_Date": "2024-04-12T00:00:00Z", "Ingested_At": "2024-04-12T00:00:00Z",
                "Content_Hash": "h", "Raw_Content": "Command injection in GlobalProtect.", "CVE_ID": cve,
                "PoC_URLs": ["https://github.com/someone/CVE-2024-3400", "https://github.com/rapid7/metasploit-framework"],
                "PoC_Details": [{"url": "https://github.com/someone/CVE-2024-3400", "stars": 150,
                                 "source": f"GitHub repository search for '{cve} poc'", "matched_on": "repo name"}],
                "Extra_Metadata": {"references": ["https://security.paloaltonetworks.com/CVE-2024-3400"],
                                   "vendor_bulletins": ["https://security.paloaltonetworks.com"]},
                "Change_Status": "UPDATED", "Change_Summary": ["new PoC link: https://github.com/someone/CVE-2024-3400"],
            },
            "pre_filter": {"category": "WEB", "matched_by": "KEYWORDS", "reason": "r", "is_in_scope": True},
            "ai_assessment": None, "priority_score": 50.0, "score_breakdown": {}, "discrepancy": None,
            "triaged_at": "2024-04-12T00:00:00Z",
        }
        with tempfile.TemporaryDirectory() as tmp:
            triaged = Path(tmp) / "triaged_candidates.json"
            triaged.write_text(json.dumps([candidate]), encoding="utf-8")
            with patch("Backend.api.data_service.TRIAGED_FILE", triaged):
                item = DataService().get_candidate_by_id(cve)

        refs = {r["url"]: r for r in item["external_references"]}
        self.assertIn("Built from the CVE ID", refs["https://nvd.nist.gov/vuln/detail/CVE-2024-3400"]["found_via"])
        self.assertIn("matched in repo name", refs["https://github.com/someone/CVE-2024-3400"]["found_via"])
        self.assertIn("Not CVE-Specific", refs["https://github.com/rapid7/metasploit-framework"]["link_type"])
        self.assertIn("NVD reference list", refs["https://security.paloaltonetworks.com/CVE-2024-3400"]["found_via"])
        self.assertIn("Hand-entered", refs["https://security.paloaltonetworks.com"]["found_via"])
        for ref in item["external_references"]:
            self.assertTrue(ref.get("found_via"), ref["url"])
        # Change tracking fields reach the dashboard untouched
        self.assertEqual(item["envelope"]["Change_Status"], "UPDATED")

if __name__ == "__main__":
    unittest.main()
