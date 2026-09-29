"""
Security Decision Engine & Lineage (Brick 4.7)

Derives sovereign, provenance-backed security decisions:
- Deterministic outcome: CLEAR, BLOCKED, REQUIRES_REVIEW, CONDITIONAL,
  INSUFFICIENT_EVIDENCE, RECONCILIATION_REQUIRED, UNKNOWN
- Full decision lineage tracking state transitions over time
- Actionable recommendations and governed action proposals
- Exact repository, commit, and artifact digest binding
"""

from __future__ import annotations

import time
import uuid
from typing import Any, Dict, List, Optional

from backend.release.models import (
    GovernedActionProposal,
    GovernedActionStatus,
    GovernedActionType,
    RiskLevel,
)
from backend.release.security.models import (
    ContradictionStatus,
    ExploitabilityAssessment,
    ReachabilityAssessment,
    RemediationCandidate,
    SecurityContradictionRecord,
    SecurityDecision,
    SecurityDecisionOutcome,
    SecurityFinding,
)
from backend.release.security.policy import PolicyEvaluationResult, SecurityPolicyEngine


class SecurityDecisionEngine:
    """
    Sovereign Controller Security Decision Engine.
    Guarantees that decisions are derived strictly from policy evaluation and verified evidence.
    """

    def __init__(self, policy_engine: Optional[SecurityPolicyEngine] = None):
        self.policy_engine = policy_engine or SecurityPolicyEngine()

    def derive_decision(
        self,
        repository: str,
        commit: str,
        tenant_id: str = "default",
        artifact_digest: Optional[str] = None,
        findings: Optional[List[SecurityFinding]] = None,
        reachability_map: Optional[Dict[str, ReachabilityAssessment]] = None,
        exploitability_map: Optional[Dict[str, ExploitabilityAssessment]] = None,
        contradictions: Optional[List[SecurityContradictionRecord]] = None,
        remediations: Optional[List[RemediationCandidate]] = None,
        is_evidence_stale: bool = False,
        unresolved_gaps: Optional[List[str]] = None,
        previous_decision: Optional[SecurityDecision] = None,
        impact_map: Optional[Dict[str, Any]] = None,
        exposure_map: Optional[Dict[str, Any]] = None,
        deployment_id: Optional[str] = None,
        service_id: Optional[str] = None,
        environment: Optional[Any] = None,
    ) -> SecurityDecision:
        """
        Derive authoritative SecurityDecision.
        """
        active_findings = findings or []
        contras = contradictions or []
        rems = remediations or []
        gaps = unresolved_gaps or []

        # 1. Execute deterministic policy evaluation
        policy_result: PolicyEvaluationResult = self.policy_engine.evaluate_policies(
            findings=active_findings,
            reachability_map=reachability_map,
            exploitability_map=exploitability_map,
            contradictions=contras,
            is_evidence_stale=is_evidence_stale,
            impact_map=impact_map,
            exposure_map=exposure_map,
            environment=environment,
        )

        outcome = policy_result.outcome

        # 2. Derive Risk Level
        if outcome == SecurityDecisionOutcome.SECURITY_BLOCKED:
            risk_level = RiskLevel.CRITICAL
        elif outcome in (SecurityDecisionOutcome.SECURITY_REQUIRES_REVIEW, SecurityDecisionOutcome.SECURITY_RECONCILIATION_REQUIRED):
            risk_level = RiskLevel.HIGH
        elif outcome in (SecurityDecisionOutcome.SECURITY_CONDITIONAL, SecurityDecisionOutcome.SECURITY_INSUFFICIENT_EVIDENCE):
            risk_level = RiskLevel.MEDIUM
        else:
            risk_level = RiskLevel.LOW

        # 3. Compile Blocking & Verified Factors
        blocking_factors: List[str] = []
        blocking_factors.extend(policy_result.blocking_reasons)
        blocking_factors.extend(policy_result.review_reasons)

        verified_factors: List[str] = []
        verified_factors.extend(policy_result.verified_factors)
        verified_factors.extend(policy_result.conditional_reasons)

        # 4. Generate Governed Action Proposals
        actions: List[GovernedActionProposal] = []
        evidence_refs: List[str] = []

        for f in active_findings:
            evidence_refs.extend(f.evidence_ids)

        if outcome == SecurityDecisionOutcome.SECURITY_BLOCKED:
            for bf in policy_result.blocking_reasons:
                actions.append(
                    GovernedActionProposal(
                        action_type=GovernedActionType.BLOCK_DEPLOYMENT,
                        target_system="deployment",
                        payload={"reason": bf, "repository": repository, "commit": commit},
                        requires_human_approval=True,
                        idempotency_key=f"sec-block-{repository}-{commit[:10]}",
                        tenant_id=tenant_id,
                    )
                )
                actions.append(
                    GovernedActionProposal(
                        action_type=GovernedActionType.CREATE_JIRA_REMEDIATION,
                        target_system="jira",
                        payload={"summary": f"Security Blocker: {bf}", "commit": commit},
                        requires_human_approval=True,
                        idempotency_key=f"sec-jira-{repository}-{commit[:10]}",
                        tenant_id=tenant_id,
                    )
                )
        elif outcome == SecurityDecisionOutcome.SECURITY_RECONCILIATION_REQUIRED:
            actions.append(
                GovernedActionProposal(
                    action_type=GovernedActionType.TRIGGER_SECURITY_SCAN,
                    target_system="security_scanner",
                    payload={"reason": "Arbitrate security contradiction with clean rescan", "commit": commit},
                    requires_human_approval=False,
                    idempotency_key=f"sec-arbitrate-rescan-{repository}-{commit[:10]}",
                    tenant_id=tenant_id,
                )
            )

        # 5. Deterministic Rationale
        if outcome == SecurityDecisionOutcome.SECURITY_CLEAR:
            rationale = "All security checks satisfied. No active, reachable, or unmitigated security vulnerabilities found."
            confidence = 1.0
        elif outcome == SecurityDecisionOutcome.SECURITY_BLOCKED:
            rationale = f"Deployment BLOCKED due to {len(blocking_factors)} active security blocker(s). Re-evaluation required after fix."
            confidence = 0.95
        elif outcome == SecurityDecisionOutcome.SECURITY_REQUIRES_REVIEW:
            rationale = "Security review required: critical/high vulnerabilities present with uncertain reachability or complex context."
            confidence = 0.85
        elif outcome == SecurityDecisionOutcome.SECURITY_CONDITIONAL:
            rationale = "Security clearance CONDITIONAL: vulnerabilities present but verified unreachable or protected by compensating controls."
            confidence = 0.90
        elif outcome == SecurityDecisionOutcome.SECURITY_RECONCILIATION_REQUIRED:
            rationale = f"Contradictory security evidence detected across {len(contras)} issue(s); reconciliation rescan required."
            confidence = 0.80
        elif outcome == SecurityDecisionOutcome.SECURITY_INSUFFICIENT_EVIDENCE:
            rationale = "Security evidence is stale, superseded, or incomplete. Reinvestigation triggered."
            confidence = 0.70
        else:
            rationale = "Inconclusive security evaluation."
            confidence = 0.50

        # 6. Lineage Tracking
        decision_id = f"secdec-{uuid.uuid4().hex[:8]}"
        now_str = "2026-09-09T12:00:00Z"

        lineage_record = {
            "decision_id": decision_id,
            "outcome": outcome.value,
            "timestamp": now_str,
            "invoked_rules": policy_result.invoked_rules,
            "blocking_count": len(blocking_factors),
        }

        lineage = []
        if previous_decision:
            lineage.extend(previous_decision.decision_lineage)
        lineage.append(lineage_record)

        return SecurityDecision(
            decision_id=decision_id,
            tenant_id=tenant_id,
            repository=repository,
            commit=commit,
            artifact_digest=artifact_digest,
            outcome=outcome,
            risk_level=risk_level,
            confidence=confidence,
            deterministic_reason=rationale,
            blocking_factors=blocking_factors,
            verified_factors=verified_factors,
            recommendations=rems,
            governed_actions=actions,
            evidence_references=list(set(evidence_refs)),
            policy_rules_invoked=policy_result.invoked_rules,
            contradictions=contras,
            unresolved_gaps=gaps,
            decision_lineage=lineage,
            timestamp=now_str,
        )
