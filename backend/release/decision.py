"""
Release Decision & Recommendation Engine (Brick 4.0)

Derives sovereign, provenance-backed release decisions from verified investigation state:
1. Deterministic outcome derivation (READY, BLOCKED, CONDITIONAL, REQUIRES_REVIEW, INSUFFICIENT_EVIDENCE).
2. Risk level and confidence computation.
3. Evidence-grounded actionable recommendations (no hallucinations).
4. Governed action proposals tied to discovered blockers.
"""

from __future__ import annotations

import hashlib
import time
import uuid
from typing import Any, Dict, List, Optional, Set, Tuple

from backend.investigation.models import GapStatus
from backend.release.investigation import ReleaseInvestigationResult
from backend.release.models import (
    GovernedActionProposal,
    GovernedActionStatus,
    GovernedActionType,
    ReleaseCandidate,
    ReleaseDecision,
    ReleaseDecisionOutcome,
    ReleaseRecommendation,
    RiskLevel,
)


class ReleaseDecisionEngine:
    """
    Sovereign Controller decision engine.
    Ensures that LLMs or external agents cannot unilaterally declare READY.
    Decisions are purely derived from verified facts in the investigation result.
    """

    def __init__(self):
        pass

    def evaluate_decision(
        self,
        investigation: Optional[ReleaseInvestigationResult] = None,
        *,
        investigation_result: Optional[ReleaseInvestigationResult] = None,
        candidate: Optional[ReleaseCandidate] = None,
        security_release_assessment: Optional[Any] = None,
    ) -> ReleaseDecision:
        """
        Derive the release readiness decision, risk level, recommendations, and governed actions.
        """
        investigation = investigation or investigation_result
        if investigation is None:
            raise ValueError("ReleaseInvestigationResult is required")
        candidate = candidate or investigation.candidate
        gaps = {g.gap_id: g for g in investigation.gaps}

        blocking_factors: List[str] = []
        verified_factors: List[str] = []
        recommendations: List[ReleaseRecommendation] = []
        actions: List[GovernedActionProposal] = []

        # 1. Inspect Outages and Failures
        if investigation.outages_detected:
            for out in investigation.outages_detected:
                blocking_factors.append(f"Provider unavailable: {out.upper()} provider outage or timeout")
                actions.append(
                    GovernedActionProposal(
                        action_type=GovernedActionType.TRIGGER_SECURITY_SCAN if out == "security" else GovernedActionType.COMMENT_ON_PR,
                        target_system=out,
                        payload={"reason": f"Provider {out} was unavailable during assessment"},
                        requires_human_approval=True,
                        idempotency_key=f"outage-retry-{out}-{candidate.release_id}",
                    )
                )

        # 2. Inspect Contradictions
        if investigation.contradictions:
            for contra in investigation.contradictions:
                blocking_factors.append(f"Cross-system contradiction: {contra.basis}")
                recommendations.append(
                    ReleaseRecommendation(
                        target_issue=contra.contradiction_id,
                        action_summary=f"Arbitrate contradiction for {contra.conflicting_subject}",
                        rationale=contra.basis,
                        current_state="RECONCILIATION_REQUIRED",
                        recommended_state="RESOLVED",
                        risk_assessment="High risk of deploying unaligned state",
                        evidence_references=[contra.claim_a_evidence_id, contra.claim_b_evidence_id],
                    )
                )

        # 3. Inspect Stale or Rejected Evidence
        for rej in investigation.rejected_evidence:
            if rej.rejection_reason == "STALE_COMMIT_EVIDENCE":
                commit_found = rej.details.get("found_commit", "unknown")[:10]
                blocking_factors.append(f"Stale validation: {rej.source_type.upper()} evidence belongs to old commit {commit_found}, not release commit {candidate.commit[:10]}")
                recommendations.append(
                    ReleaseRecommendation(
                        target_issue=rej.evidence_id,
                        action_summary=f"Re-run {rej.source_type.upper()} validation for commit {candidate.commit[:10]}",
                        rationale=f"Current release commit {candidate.commit[:10]} has not been validated by {rej.source_type.upper()}.",
                        current_state=f"Validated on commit {commit_found}",
                        recommended_state=f"Validated on commit {candidate.commit[:10]}",
                        risk_assessment="Unverified commit deployed to production",
                        evidence_references=[rej.evidence_id],
                    )
                )
            elif rej.rejection_reason == "CROSS_RELEASE_LEAKAGE":
                blocking_factors.append(f"Evidence leakage rejected: {rej.evidence_id} belongs to foreign release {rej.details.get('found_release')}")

        # 4. Evaluate Leaf Gaps
        # Code Review
        gap_cr = gaps.get("GAP-CODE-REVIEW")
        if gap_cr:
            if gap_cr.status == GapStatus.RESOLVED:
                verified_factors.append("Code review completed and approved")
            else:
                blocking_factors.append(f"Code review incomplete: {gap_cr.resolution}")
                rec_sum = "Request code review approval"
                recommendations.append(
                    ReleaseRecommendation(
                        target_issue="GAP-CODE-REVIEW",
                        action_summary=f"Obtain required code review approvals on {candidate.pull_request_id or candidate.repository}",
                        rationale=gap_cr.resolution or "Code review not approved",
                        current_state="UNAPPROVED",
                        recommended_state="APPROVED",
                        risk_assessment="Unreviewed code introduction",
                        evidence_references=gap_cr.resolution_evidence_ids,
                    )
                )
                actions.append(
                    GovernedActionProposal(
                        action_type=GovernedActionType.REQUEST_CODE_REVIEW,
                        target_system="git",
                        payload={"repository": candidate.repository, "pr_id": candidate.pull_request_id},
                        requires_human_approval=True,
                        idempotency_key=f"request-review-{candidate.release_id}",
                    )
                )

        # Rollback Plan
        gap_rb = gaps.get("GAP-ROLLBACK-PLAN")
        if gap_rb:
            if gap_rb.status == GapStatus.RESOLVED:
                verified_factors.append("Rollback procedure documented and verified")
            else:
                blocking_factors.append(f"Rollback plan missing: {gap_rb.resolution}")
                recommendations.append(
                    ReleaseRecommendation(
                        target_issue="GAP-ROLLBACK-PLAN",
                        action_summary=f"Document and test rollback procedure for {candidate.service_name}",
                        rationale="Zero documented rollback path for production release",
                        current_state="UNDOCUMENTED",
                        recommended_state="DOCUMENTED",
                        risk_assessment="Inability to revert during production outage",
                    )
                )

        # Work Items
        gap_wi = gaps.get("GAP-WORK-ITEMS")
        if gap_wi:
            if gap_wi.status == GapStatus.RESOLVED:
                verified_factors.append("Required Jira/Linear work items completed")
            else:
                blocking_factors.append(f"Work management blocker: {gap_wi.resolution}")
                recommendations.append(
                    ReleaseRecommendation(
                        target_issue="GAP-WORK-ITEMS",
                        action_summary=f"Complete unresolved blocking work items for {candidate.service_name}",
                        rationale=gap_wi.resolution or "Unresolved blocking tickets",
                        current_state="OPEN_OR_BLOCKED",
                        recommended_state="DONE",
                        risk_assessment="Incomplete feature or dependency deployment",
                        evidence_references=gap_wi.resolution_evidence_ids,
                    )
                )

        # CI/CD Validation
        gap_ci = gaps.get("GAP-CI-VALIDATION")
        if gap_ci:
            if gap_ci.status == GapStatus.RESOLVED:
                verified_factors.append("CI pipeline build and automated test suite passed")
            else:
                blocking_factors.append(f"CI validation failure: {gap_ci.resolution}")
                recommendations.append(
                    ReleaseRecommendation(
                        target_issue="GAP-CI-VALIDATION",
                        action_summary=f"Fix failing tests and re-run CI pipeline for commit {candidate.commit[:10]}",
                        rationale=gap_ci.resolution or "CI validation failed",
                        current_state="FAILED_OR_MISSING",
                        recommended_state="PASSED",
                        risk_assessment="Deploying broken build to production",
                        evidence_references=gap_ci.resolution_evidence_ids,
                    )
                )
                actions.append(
                    GovernedActionProposal(
                        action_type=GovernedActionType.COMMENT_ON_PR,
                        target_system="git",
                        payload={"pr_id": candidate.pull_request_id, "comment": f"ORACLE Release Guard: CI failed on commit {candidate.commit[:10]}."},
                        requires_human_approval=True,
                        idempotency_key=f"comment-ci-fail-{candidate.release_id}",
                    )
                )

        # Security SAST
        gap_sast = gaps.get("GAP-SECURITY-SAST")
        if gap_sast:
            if gap_sast.status == GapStatus.RESOLVED:
                verified_factors.append("SAST static security analysis clean")
            else:
                blocking_factors.append(f"Critical security finding: {gap_sast.resolution}")
                recommendations.append(
                    ReleaseRecommendation(
                        target_issue="GAP-SECURITY-SAST",
                        action_summary=f"Remediate static security vulnerability in {candidate.repository}",
                        rationale=gap_sast.resolution or "Active SAST vulnerability",
                        current_state="ACTIVE_VULNERABILITY",
                        recommended_state="REMEDIATED",
                        risk_assessment="Exploitable security defect in production",
                        evidence_references=gap_sast.resolution_evidence_ids,
                    )
                )
                actions.append(
                    GovernedActionProposal(
                        action_type=GovernedActionType.CREATE_JIRA_REMEDIATION,
                        target_system="jira",
                        payload={"summary": f"Remediate SAST finding on {candidate.service_name}", "priority": "CRITICAL"},
                        requires_human_approval=True,
                        idempotency_key=f"jira-sast-rem-{candidate.release_id}",
                    )
                )

        # Security SCA (Dependencies)
        gap_sca = gaps.get("GAP-SECURITY-SCA")
        has_conditional_sca = False
        if gap_sca:
            if gap_sca.status == GapStatus.RESOLVED:
                if "unreachable" in (gap_sca.resolution or "").lower():
                    has_conditional_sca = True
                    verified_factors.append("SCA dependency checks passed (unreachable vulnerability noted)")
                else:
                    verified_factors.append("SCA third-party dependencies verified clean")
            else:
                blocking_factors.append(f"Vulnerable dependency: {gap_sca.resolution}")
                # Try to extract package and fixed version from evidence
                pkg_info = self._extract_upgrade_recommendation(gap_sca.resolution_evidence_ids, investigation.admitted_evidence)
                action_text = f"Upgrade {pkg_info[0]} from {pkg_info[1]} to {pkg_info[2]}" if pkg_info[0] else "Upgrade vulnerable dependencies"
                recommendations.append(
                    ReleaseRecommendation(
                        target_issue="GAP-SECURITY-SCA",
                        action_summary=action_text,
                        rationale=gap_sca.resolution or "Vulnerable dependency present",
                        current_state="VULNERABLE",
                        recommended_state="UPGRADED",
                        risk_assessment="Supply chain vulnerability exploit",
                        evidence_references=gap_sca.resolution_evidence_ids,
                    )
                )
                actions.append(
                    GovernedActionProposal(
                        action_type=GovernedActionType.CREATE_JIRA_REMEDIATION,
                        target_system="jira",
                        payload={"summary": action_text, "priority": "HIGH"},
                        requires_human_approval=True,
                        idempotency_key=f"jira-sca-rem-{candidate.release_id}",
                    )
                )

        # Active Incidents
        gap_inc = gaps.get("GAP-INCIDENT-CLEAR")
        if gap_inc:
            if gap_inc.status == GapStatus.RESOLVED:
                verified_factors.append("Zero active production incidents affecting target service")
            else:
                blocking_factors.append(f"Production incident unresolved: {gap_inc.resolution}")
                recommendations.append(
                    ReleaseRecommendation(
                        target_issue="GAP-INCIDENT-CLEAR",
                        action_summary=f"Resolve active production incident affecting {candidate.service_name}",
                        rationale=gap_inc.resolution or "Active incident in progress",
                        current_state="INCIDENT_ACTIVE",
                        recommended_state="RESOLVED",
                        risk_assessment="Destabilizing production environment under active fault condition",
                        evidence_references=gap_inc.resolution_evidence_ids,
                    )
                )

        # Security Release Assessment Integration (Brick 4.8)
        sec_assess = security_release_assessment or getattr(investigation, "security_release_assessment", None)
        if sec_assess:
            if sec_assess.artifact_drift_detected:
                blocking_factors.append("Security artifact drift detected: Production deployment artifact differs in security posture from release commit.")
                recommendations.append(
                    ReleaseRecommendation(
                        target_issue="ARTIFACT_DEPLOYMENT_MISMATCH",
                        action_summary=f"Reconcile artifact drift for {candidate.service_name}",
                        rationale="Production deployment is running an artifact whose security status contradicts repository HEAD.",
                        current_state="ARTIFACT_DRIFT",
                        recommended_state="RECONCILED",
                        risk_assessment="Deploying unverified or mismatched artifact to production",
                    )
                )
            if sec_assess.is_release_blocked:
                for br in sec_assess.blocking_reasons:
                    if br not in blocking_factors:
                        blocking_factors.append(f"Security impact blocker: {br}")
            for cl in sec_assess.clusters:
                if cl.common_remediation and cl.cluster_impact_level.value in ("CRITICAL_IMPACT", "HIGH_IMPACT"):
                    actions.append(
                        GovernedActionProposal(
                            action_type=GovernedActionType.CREATE_JIRA_REMEDIATION,
                            target_system="jira",
                            payload={
                                "summary": f"Upgrade {cl.affected_package} to {cl.common_remediation.recommended_version}",
                                "priority": "CRITICAL" if cl.cluster_impact_level.value == "CRITICAL_IMPACT" else "HIGH",
                            },
                            requires_human_approval=True,
                            idempotency_key=f"jira-cluster-rem-{cl.cluster_id}-{candidate.release_id}",
                        )
                    )

        # 5. Determine Sovereign Outcome & Risk
        outcome, risk, confidence, rationale = self._compute_outcome(
            investigation=investigation,
            blocking_factors=blocking_factors,
            has_conditional_sca=has_conditional_sca,
        )

        # Governed action for release finalization
        if outcome == ReleaseDecisionOutcome.BLOCKED:
            actions.append(
                GovernedActionProposal(
                    action_type=GovernedActionType.BLOCK_DEPLOYMENT,
                    target_system="ci_cd",
                    payload={"release_id": candidate.release_id, "reason": rationale},
                    requires_human_approval=False,  # Automated safety block
                    idempotency_key=f"block-deploy-{candidate.release_id}",
                )
            )
        elif outcome == ReleaseDecisionOutcome.READY:
            actions.append(
                GovernedActionProposal(
                    action_type=GovernedActionType.APPROVE_DEPLOYMENT,
                    target_system="ci_cd",
                    payload={"release_id": candidate.release_id, "version": candidate.version},
                    requires_human_approval=True,  # Human final gate
                    idempotency_key=f"approve-deploy-{candidate.release_id}",
                )
            )

        evidence_ids = [e.evidence_id for e in investigation.admitted_evidence]
        contradiction_ids = [c.contradiction_id for c in investigation.contradictions]
        unresolved_gap_ids = [g.gap_id for g in investigation.gaps if g.status != GapStatus.RESOLVED]

        return ReleaseDecision(
            release_id=candidate.release_id,
            outcome=outcome,
            risk_level=risk,
            confidence=confidence,
            rationale=rationale,
            blocking_factors=blocking_factors,
            verified_factors=verified_factors,
            recommendations=recommendations,
            governed_actions=actions,
            evidence_item_ids=evidence_ids,
            contradiction_ids=contradiction_ids,
            unresolved_gap_ids=unresolved_gap_ids,
            investigation_id=investigation.investigation_id,
            investigation_status="RECONCILIATION_REQUIRED" if investigation.has_contradictions else ("VERIFIED" if outcome in [ReleaseDecisionOutcome.READY, ReleaseDecisionOutcome.BLOCKED, ReleaseDecisionOutcome.CONDITIONAL] else "INCOMPLETE"),
            provenance={
                "evaluated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "candidate_commit": candidate.commit,
                "engine": "ORACLE Controller 4.0",
            },
        )

    def _compute_outcome(
        self,
        investigation: ReleaseInvestigationResult,
        blocking_factors: List[str],
        has_conditional_sca: bool,
    ) -> Tuple[ReleaseDecisionOutcome, RiskLevel, float, str]:
        """
        Derive outcome, risk level, confidence, and rationale from facts.
        """
        # A. Contradictions -> REQUIRES_REVIEW or RECONCILIATION_REQUIRED
        if investigation.has_contradictions:
            return (
                ReleaseDecisionOutcome.REQUIRES_REVIEW,
                RiskLevel.HIGH,
                0.50,
                f"Release assessment halted due to unresolved cross-system contradictions: {investigation.contradictions[0].basis}",
            )

        # B. Provider Outage -> INSUFFICIENT_EVIDENCE
        if investigation.outages_detected:
            return (
                ReleaseDecisionOutcome.INSUFFICIENT_EVIDENCE,
                RiskLevel.MEDIUM,
                0.30,
                f"Cannot determine release readiness due to provider outage: {', '.join(investigation.outages_detected)}.",
            )

        # C. Hard Failures & Active Blockers -> BLOCKED
        hard_failures = [b for b in blocking_factors if not b.startswith("Stale validation:") and "INSUFFICIENT_EVIDENCE" not in b]
        if hard_failures:
            has_crit = any("critical" in b.lower() or "incident" in b.lower() or "ci validation failure" in b.lower() or "ci validation failed" in b.lower() for b in hard_failures)
            risk = RiskLevel.CRITICAL if has_crit else RiskLevel.HIGH
            return (
                ReleaseDecisionOutcome.BLOCKED,
                risk,
                0.95,
                f"Release is BLOCKED by {len(hard_failures)} active factor(s): {hard_failures[0]}.",
            )

        # D. Stale Evidence Rejection -> INSUFFICIENT_EVIDENCE
        stale_rejections = [r for r in investigation.rejected_evidence if r.rejection_reason == "STALE_COMMIT_EVIDENCE"]
        if stale_rejections:
            admitted_sources = {e.source_type for e in investigation.admitted_evidence}
            uncovered_stale = [r for r in stale_rejections if r.source_type not in admitted_sources]
            if uncovered_stale or not admitted_sources:
                target_src = uncovered_stale[0].source_type if uncovered_stale else stale_rejections[0].source_type
                return (
                    ReleaseDecisionOutcome.INSUFFICIENT_EVIDENCE,
                    RiskLevel.HIGH,
                    0.40,
                    f"Evidence for release commit {investigation.candidate.commit[:10]} is missing or stale ({target_src} was run on older commit).",
                )

        # E. General Blockers
        if blocking_factors:
            return (
                ReleaseDecisionOutcome.BLOCKED,
                RiskLevel.HIGH,
                0.95,
                f"Release is BLOCKED by {len(blocking_factors)} active factor(s): {blocking_factors[0]}.",
            )

        # E. Conditional Release
        if has_conditional_sca:
            return (
                ReleaseDecisionOutcome.CONDITIONAL,
                RiskLevel.LOW,
                0.90,
                "Release is conditionally ready: non-blocking, unreachable dependency warnings noted.",
            )

        # F. Fully Verified -> READY
        if investigation.is_root_resolved:
            return (
                ReleaseDecisionOutcome.READY,
                RiskLevel.LOW,
                0.99,
                "All verification criteria satisfied across source control, CI/CD, work management, and security.",
            )

        # Default fallback
        return (
            ReleaseDecisionOutcome.UNKNOWN,
            RiskLevel.MEDIUM,
            0.50,
            "Investigation finished without resolving root release gap.",
        )

    def _extract_upgrade_recommendation(
        self,
        evidence_ids: List[str],
        admitted: List[Evidence],
    ) -> Tuple[str, str, str]:
        """Extract (package, current_version, fixed_version) from security evidence."""
        for ev in admitted:
            if ev.evidence_id in evidence_ids:
                meta = ev.metadata or {}
                pkg = meta.get("package")
                fixed = meta.get("fixed_version")
                if pkg and fixed:
                    return pkg, meta.get("current_version", "current"), fixed
        return "", "", ""
