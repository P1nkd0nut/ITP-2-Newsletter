"""
Multi-Factor Priority Scoring Engine & CVSS Anomaly Gate (Task 2.4).
Implements the revised 100-point AI-driven ranking formula:
- Active Exploitation (CISA KEV): 40 pts
- AI Practical Severity & Exploitability (Ollama/LLM): 40 pts
- Public PoC Availability (GitHub Exploit): 20 pts
Total = 100 points.

Also implements the CVSS Discrepancy Detector:
Flags any item where |AI_Severity - CVSS| >= 4.0 for investigation and troubleshooting.
"""
from datetime import datetime, timezone
import logging
from typing import Set, Optional, Tuple, List, Dict
from Backend.ingestion.models import StagingEnvelope
from Backend.triage.models import (
    TriagedCandidate,
    PreFilterDecision,
    AISeverityAssessment,
    CVSSDiscrepancy,
    ScopeCategory,
)
from Backend.triage.pre_filter import PentestPreFilter
from Backend.triage.ai_evaluator import AISeverityEvaluator

logger = logging.getLogger(__name__)

DISCREPANCY_THRESHOLD = 4.0


class PriorityScoringEngine:
    """Orchestrates Scope Pre-Filtering, AI Severity Scoring, and Anomaly Detection."""

    def __init__(
        self,
        kev_catalog: Optional[Set[str]] = None,
        pre_filter: Optional[PentestPreFilter] = None,
        ai_evaluator: Optional[AISeverityEvaluator] = None,
    ):
        self.kev_catalog = kev_catalog or set()
        self.pre_filter = pre_filter or PentestPreFilter()
        self.ai_evaluator = ai_evaluator or AISeverityEvaluator()

    def process_envelope(self, envelope: StagingEnvelope) -> TriagedCandidate:
        """
        Processes a single staging envelope through:
        1. Scope Pre-Filter Gate
        2. AI Severity Evaluation (for in-scope items)
        3. 100-pt Priority Scoring
        4. CVSS Anomaly / Discrepancy Detection
        """
        triaged_at = datetime.now(timezone.utc).isoformat()

        # Step 1: Scope Pre-Filter Gate
        pre_filter_decision = self.pre_filter.evaluate(envelope)

        # If Out of Scope (e.g. printer spooler, firmware), do not score for weekly newsletter
        if not pre_filter_decision.is_in_scope:
            return TriagedCandidate(
                envelope=envelope,
                pre_filter=pre_filter_decision,
                ai_assessment=None,
                priority_score=0.0,
                score_breakdown={
                    "cisa_kev_points": 0.0,
                    "ai_severity_points": 0.0,
                    "poc_points": 0.0,
                },
                discrepancy=None,
                triaged_at=triaged_at,
            )

        # Step 2: AI Practical Severity Evaluation (Qwen 2.5)
        ai_assessment = self.ai_evaluator.evaluate(envelope)

        # Step 3: Compute 100-Point Priority Score
        score, breakdown = self._calculate_100pt_score(envelope, ai_assessment)

        # Step 4: CVSS vs AI Discrepancy Check
        discrepancy = self._detect_cvss_discrepancy(envelope.CVSS, ai_assessment.severity_score)

        return TriagedCandidate(
            envelope=envelope,
            pre_filter=pre_filter_decision,
            ai_assessment=ai_assessment,
            priority_score=score,
            score_breakdown=breakdown,
            discrepancy=discrepancy,
            triaged_at=triaged_at,
        )

    def _calculate_100pt_score(
        self, envelope: StagingEnvelope, ai_assessment: AISeverityAssessment
    ) -> Tuple[float, Dict[str, float]]:
        """
        100-Point Scoring Breakdown:
        1. CISA KEV Active Weaponization: 40 pts
        2. AI Practical Severity:         40 pts max ((severity / 10.0) * 40.0)
        3. Public PoC Availability:       20 pts
        """
        # 1. CISA KEV (40 pts)
        is_kev = bool(envelope.KEV_Status) or (
            envelope.CVE_ID is not None and envelope.CVE_ID.upper() in self.kev_catalog
        )
        kev_points = 40.0 if is_kev else 0.0

        # 2. AI Severity (40 pts max)
        ai_points = round((ai_assessment.severity_score / 10.0) * 40.0, 2)

        # 3. Public GitHub PoC (20 pts)
        has_poc = bool(envelope.PoC_URLs) or bool(envelope.PoC_Details)
        poc_points = 20.0 if has_poc else 0.0

        total_score = round(kev_points + ai_points + poc_points, 2)
        breakdown = {
            "cisa_kev_points": kev_points,
            "ai_severity_points": ai_points,
            "poc_points": poc_points,
        }
        return total_score, breakdown

    def _detect_cvss_discrepancy(
        self, cvss: Optional[float], ai_severity: float
    ) -> CVSSDiscrepancy:
        """
        Detects if official CVSS and AI assessment diverge by >= 4.0 points.
        """
        if cvss is None:
            return CVSSDiscrepancy(
                cvss_score=None,
                ai_severity=ai_severity,
                delta=0.0,
                is_discrepancy=False,
                troubleshoot_note="No official CVSS assigned yet. AI assessment serves as primary baseline.",
            )

        delta = round(abs(ai_severity - cvss), 2)
        is_discrepancy = delta >= DISCREPANCY_THRESHOLD
        note = None

        if is_discrepancy:
            if cvss > ai_severity:
                note = (
                    f"CVSS is significantly higher than AI severity (CVSS: {cvss} vs AI: {ai_severity}, delta={delta}). "
                    "Likely an inflated Day-0 worst-case default score by vendor; AI identified restricted operational attack conditions."
                )
            else:
                note = (
                    f"AI severity is significantly higher than CVSS (AI: {ai_severity} vs CVSS: {cvss}, delta={delta}). "
                    "NVD score appears underestimated; AI identified practical unauthenticated RCE or Auth Bypass exploit primitives."
                )

        return CVSSDiscrepancy(
            cvss_score=cvss,
            ai_severity=ai_severity,
            delta=delta,
            is_discrepancy=is_discrepancy,
            troubleshoot_note=note,
        )

    def triage_batch(self, envelopes: List[StagingEnvelope]) -> List[TriagedCandidate]:
        """Triages and scores a list of envelopes, sorted by priority score descending."""
        candidates = [self.process_envelope(env) for env in envelopes]
        candidates.sort(key=lambda c: c.priority_score, reverse=True)
        return candidates
