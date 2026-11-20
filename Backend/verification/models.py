"""
Data models for the Deterministic Source-Verification Gate (Task 3.2).
"""
from typing import List
from pydantic import BaseModel, Field


class DraftCard(BaseModel):
    """
    A newsletter card written by the AI summariser (Task 3.1).
    Only these free-text fields are AI-written, so only these are audited.
    Structured fields (CVE ID, CVSS, CWE, URL) come straight from the envelope.
    """
    mechanism: str = Field(..., description="What the flaw is and how it works")
    impact: str = Field(..., description="What an attacker gains and which versions are affected")
    testing_syntax: List[str] = Field(default_factory=list, description="Commands to test for the flaw")
    remediation: str = Field(default="", description="How to fix it")
    references: List[str] = Field(default_factory=list, description="Links cited by the card")


class CheckFailure(BaseModel):
    """One fact in the draft that could not be found in the source."""
    check: str = Field(..., description="CVE_ID, VERSION, CVSS, CWE, VENDOR_PRODUCT, COMMAND, IMPACT or URL")
    value: str = Field(..., description="The exact text that failed")
    reason: str = Field(..., description="Why it failed")


class VerificationResult(BaseModel):
    """Outcome of running a draft card through the gate."""
    passed: bool
    status: str = Field(..., description="PASSED or QUARANTINED")
    checks_run: int = Field(..., description="How many individual facts were checked")
    failures: List[CheckFailure] = Field(default_factory=list)
    attempts: int = Field(default=1, description="1 = first draft, 2 = after one regeneration")
