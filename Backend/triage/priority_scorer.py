"""
Multi-Factor Priority Scoring Engine & CVSS Anomaly Gate (Task 2.4).
Implements the revised 100-point AI-driven ranking formula:
- Active Exploitation (CISA KEV): 40 pts
- AI Practical Severity & Exploitability (Ollama/LLM): 40 pts
- Public PoC Availability (GitHub Exploit): 20 pts
Total = 100 points.

Also implements the CVSS Discrepancy Detector:
Flags any item where |AI_Severity - CVSS| >= 4.0 for investigation and troubleshooting.

Items are grouped by CVE ID before scoring (plan Task 2.4), so an NVD record,
its CISA KEV entry, its GitHub advisory and any PoC or write-up are scored as
one story: each one gets the KEV and PoC points if any item in the story has
them. Items with no CVE ID are scored on their own.
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

    def process_envelope(
        self,
        envelope: StagingEnvelope,
        cached_ai: Optional[AISeverityAssessment] = None,
        story: Optional[List[StagingEnvelope]] = None,
    ) -> TriagedCandidate:
        """
        Processes a single staging envelope through:
        1. Scope Pre-Filter Gate
        2. AI Severity Evaluation (for in-scope items)
        3. 100-pt Priority Scoring
        4. CVSS Anomaly / Discrepancy Detection

        A cached_ai assessment (from an earlier run of the same unchanged item)
        skips the AI call; the score is still recomputed with current KEV/PoC data.
        `story` is every envelope sharing this one's CVE ID (itself included); its
        KEV and PoC signals count for the whole story.
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
        ai_assessment = cached_ai or self.ai_evaluator.evaluate(envelope)

        # Step 3: Compute 100-Point Priority Score
        score, breakdown = self._calculate_100pt_score(envelope, ai_assessment, story)

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
            story_item_ids=[e.Item_ID for e in story] if story and len(story) > 1 else [],
        )

    def _calculate_100pt_score(
        self,
        envelope: StagingEnvelope,
        ai_assessment: AISeverityAssessment,
        story: Optional[List[StagingEnvelope]] = None,
    ) -> Tuple[float, Dict[str, float]]:
        """
        100-Point Scoring Breakdown:
        1. CISA KEV Active Weaponization: 40 pts
        2. AI Practical Severity:         40 pts max ((severity / 10.0) * 40.0)
        3. Public PoC Availability:       20 pts
        """
        members = story or [envelope]

        # 1. CISA KEV (40 pts)
        is_kev = any(bool(e.KEV_Status) for e in members) or (
            envelope.CVE_ID is not None and envelope.CVE_ID.upper() in self.kev_catalog
        )
        kev_points = 40.0 if is_kev else 0.0

        # 2. AI Severity (40 pts max)
        ai_points = round((ai_assessment.severity_score / 10.0) * 40.0, 2)

        # 3. Public GitHub PoC (20 pts)
        has_poc = any(bool(e.PoC_URLs) or bool(e.PoC_Details) for e in members)
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
                    f"CVSS is much higher than the AI severity (CVSS: {cvss} vs AI: {ai_severity}, delta={delta}). "
                    "Possible reasons: a worst-case default score on a new record, or attack conditions the AI judged "
                    "restrictive. Review the advisory before relying on either score."
                )
            else:
                note = (
                    f"AI severity is much higher than CVSS (AI: {ai_severity} vs CVSS: {cvss}, delta={delta}). "
                    "Possible reasons: the official score understates the practical impact, or the AI overrated it. "
                    "Review the advisory before relying on either score."
                )

        return CVSSDiscrepancy(
            cvss_score=cvss,
            ai_severity=ai_severity,
            delta=delta,
            is_discrepancy=is_discrepancy,
            troubleshoot_note=note,
        )

    def triage_batch(
        self,
        envelopes: List[StagingEnvelope],
        cached_ai: Optional[Dict[str, AISeverityAssessment]] = None,
    ) -> List[TriagedCandidate]:
        """
        Triages and scores a list of envelopes, sorted by priority score descending.
        cached_ai maps Item_ID to a reusable assessment for items that have not changed.
        """
        cached_ai = cached_ai or {}
        stories = group_by_cve(envelopes)
        candidates = [
            self.process_envelope(env, cached_ai.get(env.Item_ID), stories.get((env.CVE_ID or "").upper()))
            for env in envelopes
        ]
        candidates.sort(key=lambda c: c.priority_score, reverse=True)
        return candidates


def group_by_cve(envelopes: List[StagingEnvelope]) -> Dict[str, List[StagingEnvelope]]:
    """CVE ID (upper case) -> every envelope reporting it. Items with no CVE ID are left out."""
    stories: Dict[str, List[StagingEnvelope]] = {}
    for env in envelopes:
        if env.CVE_ID:
            stories.setdefault(env.CVE_ID.upper(), []).append(env)
    return stories


def reusable_assessments(
    previous: List[TriagedCandidate], envelopes: List[StagingEnvelope]
) -> Dict[str, AISeverityAssessment]:
    """
    AI assessments from a previous triage run that still apply: same item, same
    source text (Content_Hash) and title, and scored by a real model rather than
    the heuristic fallback (those are worth retrying).
    """
    prev_by_id = {c.envelope.Item_ID: c for c in previous}
    reusable: Dict[str, AISeverityAssessment] = {}
    for env in envelopes:
        old = prev_by_id.get(env.Item_ID)
        if not old or not old.ai_assessment:
            continue
        if old.envelope.Content_Hash != env.Content_Hash or old.envelope.Title != env.Title:
            continue
        if old.ai_assessment.evaluated_by == "heuristic_engine":
            continue
        reusable[env.Item_ID] = old.ai_assessment
    return reusable
