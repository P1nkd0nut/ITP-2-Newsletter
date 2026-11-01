"""
Data models for the GroundedCVE Ingestion Staging Envelope.
Strictly implements the specification in Task 1.3.
"""
from enum import Enum
from typing import List, Optional, Union, Dict, Any
from pydantic import BaseModel, ConfigDict, Field


class SourceType(str, Enum):
    NVD = "NVD"
    CISA_KEV = "CISA_KEV"
    PORTSWIGGER = "PORTSWIGGER"
    PROJECT_ZERO = "PROJECT_ZERO"
    GITHUB_ADVISORY = "GITHUB_ADVISORY"
    FRIDA = "FRIDA"
    ANDROID_BULLETIN = "ANDROID_BULLETIN"
    APPLE_SECURITY = "APPLE_SECURITY"
    GITHUB_POC = "GITHUB_POC"
    OTHER = "OTHER"


class PoCReference(BaseModel):
    """Metadata for public PoC repository."""
    url: str
    stars: int = 0
    author: Optional[str] = None
    created_at: Optional[str] = None
    description: Optional[str] = None
    source: Optional[str] = None  # Where the link was found, shown on the dashboard
    matched_on: Optional[str] = None  # What tied it to the CVE (repo name, description, NVD tag)


class StagingEnvelope(BaseModel):
    """
    Standardised JSON Staging Envelope for GroundedCVE (Task 1.3).
    
    Raw_Content is preserved unmodified for subsequent verification gate
    and heading-aware chunking.
    """
    # Always present fields
    Item_ID: str = Field(..., description="Unique deterministic identifier for the ingested item")
    Source_Type: SourceType = Field(..., description="Intelligence source category")
    Title: str = Field(..., description="Title of disclosure, write-up or advisory")
    Source_URL: str = Field(..., description="Canonical source URL")
    Published_Date: str = Field(..., description="ISO 8601 publication timestamp")
    Ingested_At: str = Field(..., description="ISO 8601 timestamp when fetched")
    Content_Hash: str = Field(..., description="SHA-256 digest of Raw_Content for deduplication & verification")
    Raw_Content: str = Field(..., description="Verbatim raw content uncleaned and unparsed")

    # Optional fields
    CVE_ID: Optional[str] = Field(default=None, description="Primary CVE identifier (e.g. CVE-2024-0044)")
    Vendor_Product: Optional[str] = Field(default=None, description="Affected vendor and product name")
    Affected_Versions: Optional[Union[List[str], str]] = Field(
        default=None, description="Affected version strings or ranges"
    )
    CVSS: Optional[float] = Field(default=None, description="CVSS base score (e.g. 7.8)")
    CVSS_Version: Optional[str] = Field(default=None, description="CVSS metric version ('3.1' or '4.0')")
    CWE: Optional[Union[List[str], str]] = Field(default=None, description="Associated CWE identifiers")
    KEV_Status: Optional[bool] = Field(default=None, description="True if cataloged in CISA KEV")
    PoC_URLs: Optional[List[str]] = Field(default=None, description="List of public PoC URLs")
    PoC_Details: Optional[List[PoCReference]] = Field(
        default=None, description="Detailed PoC repository metadata if available"
    )
    Extra_Metadata: Optional[Dict[str, Any]] = Field(
        default=None, description="Additional source-specific structured attributes"
    )

    # Change tracking across ingestion runs (set by change_tracker)
    Change_Status: Optional[str] = Field(default=None, description="NEW, UPDATED or UNCHANGED versus the previous run")
    Change_Summary: Optional[List[str]] = Field(default=None, description="What differs from the previous run, if UPDATED")
    First_Seen: Optional[str] = Field(default=None, description="ISO 8601 timestamp of the first run that fetched this item")
    Last_Seen: Optional[str] = Field(default=None, description="ISO 8601 timestamp of the latest run that fetched this item")
    Last_Changed: Optional[str] = Field(default=None, description="ISO 8601 timestamp of the run that last saw it change")
    Last_Checked: Optional[str] = Field(default=None, description="ISO 8601 timestamp of the last time the source was checked for updates")

    model_config = ConfigDict(
        populate_by_name=True,
        json_schema_extra={
            "example": {
                "Item_ID": "cve-2024-0044",
                "Source_Type": "NVD",
                "Title": "CVE-2024-0044 - Android Package Installer Isolation Bypass",
                "Source_URL": "https://nvd.nist.gov/vuln/detail/CVE-2024-0044",
                "Published_Date": "2024-03-04T00:00:00Z",
                "Ingested_At": "2026-09-28T12:00:00Z",
                "Content_Hash": "a3f5...",
                "Raw_Content": "In createSessionInternal of PackageInstallerSession.java...",
                "CVE_ID": "CVE-2024-0044",
                "Vendor_Product": "Google Android",
                "Affected_Versions": ["12", "13", "14"],
                "CVSS": 7.8,
                "CVSS_Version": "3.1",
                "CWE": ["CWE-20"],
                "KEV_Status": False,
                "PoC_URLs": ["https://github.com/example/cve-2024-0044-poc"]
            }
        },
    )
