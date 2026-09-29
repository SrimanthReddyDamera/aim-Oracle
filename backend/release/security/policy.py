"""
Security Policy Engine (Brick 4.7)

Implements deterministic controller-enforced security policies:
- CRITICAL + CONFIRMED_REACHABLE → SECURITY_BLOCKED
- CRITICAL + REACHABILITY_UNKNOWN → SECURITY_REQUIRES_REVIEW
- HIGH + CONFIRMED_REACHABLE → SECURITY_BLOCKED (or policy-dependent)
- VULNERABLE + CONFIRMED_UNREACHABLE → SECURITY_CONDITIONAL / SECURITY_CLEAR
- STALE_EVIDENCE → SECURITY_INSUFFICIENT_EVIDENCE
- CONTRADICTORY_EVIDENCE → SECURITY_RECONCILIATION_REQUIRED
- MISSING_REQUIRED_SCANS → SECURITY_INSUFFICIENT_EVIDENCE

CRITICAL INVARIANT:
- Controller sovereignty is absolute.
- LLM output or advisory suggestions NEVER directly determine policy evaluation outcomes.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple
from pydantic import BaseModel, Field

from backend.release.security.models import (
    ContradictionStatus,
    ExploitabilityAssessment,
    ExploitabilityLevel,
    FindingStatus,
    ReachabilityAssessment,
    ReachabilityStatus,
    SecurityContradictionRecord,
    SecurityDecisionOutcome,
    SecurityFinding,
    SecurityPolicyRule,
    SecuritySeverity,
)


class PolicyEvaluationResult(BaseModel):
    """Deliverable of security policy evaluation."""
    outcome: SecurityDecisionOutcome
    blocking_reasons: List[str] = Field(default_factory=list)
    review_reasons: List[str] = Field(default_factory=list)
    conditional_reasons: List[str] = Field(default_factory=list)
    verified_factors: List[str] = Field(default_factory=list)
    invoked_rules: List[str] = Field(default_factory=list)


class SecurityPolicyEngine:
    """
    Deterministic security policy evaluation engine.
    Applies strict controller rules over verified security findings, reachability traces,
    and contradiction states.
    """

    def __init__(
        self,
        block_high_reachable: bool = True,
        allow_unreachable_conditional: bool = True,
        require_all_scanners: bool = False,
    ):
        self.block_high_reachable = block_high_reachable
        self.allow_unreachable_conditional = allow_unreachable_conditional
        self.require_all_scanners = require_all_scanners

    def evaluate_policies(
        self,
        findings: List[SecurityFinding],
        reachability_map: Optional[Dict[str, ReachabilityAssessment]] = None,
        exploitability_map: Optional[Dict[str, ExploitabilityAssessment]] = None,
        contradictions: Optional[List[SecurityContradictionRecord]] = None,
        is_evidence_stale: bool = False,
        missing_scanners: Optional[List[str]] = None,
        impact_map: Optional[Dict[str, Any]] = None,
        exposure_map: Optional[Dict[str, Any]] = None,
        environment: Optional[Any] = None,
        artifact: Optional[Any] = None,
        deployment: Optional[Any] = None,
        verifications: Optional[List[Any]] = None,
        compensating_controls: Optional[List[Any]] = None,
    ) -> PolicyEvaluationResult:
        """
        Execute deterministic policy rules. Evaluated in order of precedence:
        1. Stale / Missing Evidence -> INSUFFICIENT_EVIDENCE
        2. Failed Rescan Verifications -> BLOCKED
        3. Contradictions -> RECONCILIATION_REQUIRED
        4. Blockers (Critical Impact / Critical Reachable) -> BLOCKED
        5. Review Required (Critical Unknown) -> REQUIRES_REVIEW
        6. Conditional (Unreachable / Mitigated / Dev) -> CONDITIONAL
        7. Clean -> CLEAR
        """
        invoked_rules: List[str] = []
        blocking: List[str] = []
        review: List[str] = []
        conditional: List[str] = []
        verified: List[str] = []

        # 1. Stale or Missing Evidence Policy
        if is_evidence_stale:
            invoked_rules.append("RULE-SEC-STALE-EVIDENCE")
            return PolicyEvaluationResult(
                outcome=SecurityDecisionOutcome.SECURITY_INSUFFICIENT_EVIDENCE,
                blocking_reasons=["Security scan evidence is stale or belongs to a superseded commit; reinvestigation required."],
                invoked_rules=invoked_rules,
            )

        # 1b. Failed Closed-Loop Rescan Verifications
        if verifications:
            for v in verifications:
                v_stat = getattr(v, "status", None)
                v_stat_str = v_stat.value if hasattr(v_stat, "value") else str(v_stat)
                if "STILL_VULNERABLE" in v_stat_str or "FAILED" in v_stat_str:
                    invoked_rules.append("RULE-SEC-RESCAN-FAILED")
                    blocking.append(f"Remediation verification failed for finding {getattr(v, 'finding_id', '')}: Rescan confirms vulnerability still active.")
            if blocking:
                return PolicyEvaluationResult(
                    outcome=SecurityDecisionOutcome.SECURITY_BLOCKED,
                    blocking_reasons=blocking,
                    invoked_rules=invoked_rules,
                )

        if missing_scanners and self.require_all_scanners:
            invoked_rules.append("RULE-SEC-MISSING-SCANS")
            return PolicyEvaluationResult(
                outcome=SecurityDecisionOutcome.SECURITY_INSUFFICIENT_EVIDENCE,
                blocking_reasons=[f"Required security scanner(s) missing or failed: {', '.join(missing_scanners)}."],
                invoked_rules=invoked_rules,
            )

        # 2. Contradiction Policy
        contras = contradictions or []
        active_contras = [c for c in contras if getattr(c, "status", None) == ContradictionStatus.CONTRADICTED]
        if active_contras:
            invoked_rules.append("RULE-SEC-CONTRADICTION-ARBITRATION")
            reasons = [f"Security contradiction detected: {c.explanation}" for c in active_contras]
            return PolicyEvaluationResult(
                outcome=SecurityDecisionOutcome.SECURITY_RECONCILIATION_REQUIRED,
                blocking_reasons=reasons,
                invoked_rules=invoked_rules,
            )

        # If no active findings, security is clear
        active_findings = [f for f in findings if f.status == FindingStatus.ACTIVE]
        if not active_findings:
            invoked_rules.append("RULE-SEC-ALL-CLEAR")
            verified.append("All security scanners report clean or resolved findings.")
            return PolicyEvaluationResult(
                outcome=SecurityDecisionOutcome.SECURITY_CLEAR,
                verified_factors=verified,
                invoked_rules=invoked_rules,
            )

        # 3. Evaluate Active Findings against Reachability, Exploitability & Multi-dimensional Impact
        reach_map = reachability_map or {}
        exp_map = exploitability_map or {}
        imp_map = impact_map or {}

        for f in active_findings:
            imp = imp_map.get(f.finding_id)
            if imp:
                if getattr(imp, "artifact_drift_detected", False):
                    invoked_rules.append("RULE-SEC-ARTIFACT-DRIFT-BLOCK")
                    blocking.append(
                        f"Artifact drift detected: Deployed artifact contains active vulnerability {f.cve or f.finding_id} ({imp.rationale})."
                    )
                    continue
                if getattr(imp, "impact_level", None) == "NEGLIGIBLE_IMPACT":
                    invoked_rules.append("RULE-SEC-NEGLIGIBLE-IMPACT")
                    conditional.append(
                        f"Finding {f.finding_id} has negligible impact: {imp.rationale}."
                    )
                    continue
                if getattr(imp, "impact_level", None) == "CRITICAL_IMPACT":
                    invoked_rules.append("RULE-SEC-CRITICAL-IMPACT-BLOCK")
                    blocking.append(
                        f"CRITICAL impact vulnerability ({f.cve or f.finding_id}) in {f.package or f.file}: {imp.rationale}."
                    )
                    continue

            reach = reach_map.get(f.finding_id) or reach_map.get(f.package or "")
            r_status = reach.status if reach else ReachabilityStatus.REACHABILITY_UNKNOWN

            exp = exp_map.get(f.finding_id)
            exp_level = exp.level if exp else None

            # Policy Rule: Critical + Confirmed Reachable -> BLOCK
            if f.severity == SecuritySeverity.CRITICAL and r_status == ReachabilityStatus.CONFIRMED_REACHABLE:
                invoked_rules.append("RULE-SEC-CRITICAL-REACHABLE-BLOCK")
                blocking.append(
                    f"CRITICAL vulnerability ({f.cve or f.finding_id}) in {f.package or f.file} is CONFIRMED REACHABLE."
                )

            # Policy Rule: Critical + Reachability Unknown -> REQUIRES_REVIEW
            elif f.severity == SecuritySeverity.CRITICAL and r_status == ReachabilityStatus.REACHABILITY_UNKNOWN:
                invoked_rules.append("RULE-SEC-CRITICAL-UNKNOWN-REVIEW")
                review.append(
                    f"CRITICAL vulnerability ({f.cve or f.finding_id}) in {f.package or f.file} has UNKNOWN reachability; requires security team review."
                )

            # Policy Rule: High + Confirmed Reachable -> BLOCK / REVIEW
            elif f.severity == SecuritySeverity.HIGH and r_status == ReachabilityStatus.CONFIRMED_REACHABLE:
                if self.block_high_reachable:
                    invoked_rules.append("RULE-SEC-HIGH-REACHABLE-BLOCK")
                    blocking.append(
                        f"HIGH severity vulnerability ({f.cve or f.finding_id}) in {f.package or f.file} is CONFIRMED REACHABLE."
                    )
                else:
                    invoked_rules.append("RULE-SEC-HIGH-REACHABLE-REVIEW")
                    review.append(
                        f"HIGH severity vulnerability ({f.cve or f.finding_id}) in {f.package or f.file} is CONFIRMED REACHABLE; review required."
                    )

            # Policy Rule: Vulnerable + Confirmed Unreachable -> CONDITIONAL
            elif r_status == ReachabilityStatus.UNREACHABLE:
                invoked_rules.append("RULE-SEC-UNREACHABLE-CONDITIONAL")
                conditional.append(
                    f"Vulnerability ({f.cve or f.finding_id}) in {f.package or f.file} ({f.severity.value}) is verified UNREACHABLE (dead code/uninvoked symbol)."
                )

            # Policy Rule: Potentially Reachable Critical / High
            elif r_status == ReachabilityStatus.POTENTIALLY_REACHABLE and f.severity in (SecuritySeverity.CRITICAL, SecuritySeverity.HIGH):
                invoked_rules.append("RULE-SEC-POTENTIAL-HIGH-REVIEW")
                review.append(
                    f"{f.severity.value} vulnerability ({f.cve or f.finding_id}) in {f.package or f.file} is POTENTIALLY REACHABLE via internal calls."
                )

            # Policy Rule: Medium / Low findings
            else:
                invoked_rules.append("RULE-SEC-LOW-MEDIUM-ADVISORY")
                conditional.append(
                    f"{f.severity.value} finding ({f.finding_id}) accepted under standard release threshold."
                )

        # 4. Synthesize sovereign outcome
        if blocking:
            return PolicyEvaluationResult(
                outcome=SecurityDecisionOutcome.SECURITY_BLOCKED,
                blocking_reasons=blocking,
                review_reasons=review,
                conditional_reasons=conditional,
                invoked_rules=invoked_rules,
            )

        if review:
            return PolicyEvaluationResult(
                outcome=SecurityDecisionOutcome.SECURITY_REQUIRES_REVIEW,
                review_reasons=review,
                conditional_reasons=conditional,
                invoked_rules=invoked_rules,
            )

        if conditional:
            return PolicyEvaluationResult(
                outcome=SecurityDecisionOutcome.SECURITY_CONDITIONAL if self.allow_unreachable_conditional else SecurityDecisionOutcome.SECURITY_REQUIRES_REVIEW,
                conditional_reasons=conditional,
                invoked_rules=invoked_rules,
            )

        return PolicyEvaluationResult(
            outcome=SecurityDecisionOutcome.SECURITY_CLEAR,
            verified_factors=verified or ["All security criteria met."],
            invoked_rules=invoked_rules,
        )
