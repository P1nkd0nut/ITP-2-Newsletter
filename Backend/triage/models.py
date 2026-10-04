"""
Pydantic data models for the GroundedCVE Triage & Scoring Architecture.
Strictly implements the Scope Pre-Filter and AI Severity Scoring specifications.
"""
from enum import Enum
from typing import Dict, Optional, Any
from pydantic import BaseModel, Field
from Backend.ingestion.models import StagingEnvelope


class ScopeCategory(str, Enum):
    """Target pentesting ecosystem category."""
    WEB = "WEB"
    MOBILE = "MOBILE"
    OUT_OF_SCOPE = "OUT_OF_SCOPE"


class PreFilterDecision(BaseModel):
    """Evaluation result from the dedicated Scope Pre-Filter Gate."""
    category: ScopeCategory = Field(..., description="Target category: WEB, MOBILE, or OUT_OF_SCOPE")
    matched_by: str = Field(..., description="Mechanism that matched: SOURCE_ORIGIN, CWE_TAXONOMY, KEYWORDS, NEGATIVE_HEURISTIC")
    reason: str = Field(..., description="Human-readable justification for the categorization")
    is_in_scope: bool = Field(..., description="True if item belongs to Web or Mobile pentesting domain")


class AISeverityAssessment(BaseModel):
    """Evaluated by LLM (Qwen 2.5) assessing practical offensive impact."""
    severity_score: float = Field(..., ge=0.0, le=10.0, description="AI severity rating from 0.0 (negligible) to 10.0 (critical)")
    offensive_impact: str = Field(..., description="E.g. Remote Code Execution, Authentication Bypass, Privilege Escalation, DoS")
    exploitability: str = Field(..., description="CRITICAL, HIGH, MEDIUM, or LOW")
    reasoning: str = Field(..., description="Concise rationale explaining the offensive severity decision")
    evaluated_by: str = Field(..., description="Model identifier or heuristic engine name")


class CVSSDiscrepancy(BaseModel):
    """
    Sanity check comparing the LLM severity assessment against vendor CVSS.
    Triggers an anomaly flag if the delta is >= 4.0 for manual/automated troubleshooting.
    """
    cvss_score: Optional[float] = Field(default=None, description="Official CVSS base score if available")
    ai_severity: float = Field(..., description="AI severity score (0.0 to 10.0)")
    delta: float = Field(..., description="Absolute difference |AI_Severity - CVSS|")
    is_discrepancy: bool = Field(..., description="True if delta >= 4.0")
    troubleshoot_note: Optional[str] = Field(default=None, description="Root-cause diagnostic explanation")


class TriagedCandidate(BaseModel):
    """A completely triaged, pre-filtered, and scored vulnerability candidate."""
    envelope: StagingEnvelope = Field(..., description="Original raw staging envelope")
    pre_filter: PreFilterDecision = Field(..., description="Pre-filter scope determination")
    ai_assessment: Optional[AISeverityAssessment] = Field(default=None, description="AI practical severity output")
    priority_score: float = Field(default=0.0, ge=0.0, le=100.0, description="Overall ranking score out of 100.0")
    score_breakdown: Dict[str, float] = Field(default_factory=dict, description="Point allocations: KEV, AI, PoC")
    discrepancy: Optional[CVSSDiscrepancy] = Field(default=None, description="CVSS vs AI sanity check")
    triaged_at: str = Field(..., description="ISO 8601 timestamp of triage completion")
