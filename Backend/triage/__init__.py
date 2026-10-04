"""
GroundedCVE Triage & Scoring Package (Phase 2, Tasks 1.2 & 2.4).
Provides:
- Scope Pre-Filter Gate (Web vs Mobile isolation)
- AI Practical Severity & Exploitability Assessor (Ollama/LLM)
- 100-Point Priority Scorer & CVSS Discrepancy Anomaly Detector
"""
from Backend.triage.models import ScopeCategory, PreFilterDecision, AISeverityAssessment, CVSSDiscrepancy, TriagedCandidate
from Backend.triage.pre_filter import PentestPreFilter
from Backend.triage.ai_evaluator import AISeverityEvaluator
from Backend.triage.priority_scorer import PriorityScoringEngine

__all__ = [
    "ScopeCategory",
    "PreFilterDecision",
    "AISeverityAssessment",
    "CVSSDiscrepancy",
    "TriagedCandidate",
    "PentestPreFilter",
    "AISeverityEvaluator",
    "PriorityScoringEngine",
]
