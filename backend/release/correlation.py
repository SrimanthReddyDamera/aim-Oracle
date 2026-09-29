"""
Cross-System Correlation, Entity/Version Safety, & Contradiction Detection (Brick 4.0)

Enforces strict invariants across source control, work management, CI/CD, and security:
1. Entity & Version Safety: Rejects cross-release leakage, foreign repositories, and mismatched commits.
2. Temporal Reasoning: Detects stale CI runs or security scans older than the current release commit.
3. Cross-System Correlation: Links Git PRs, Jira work items, CI runs, and Security findings into unified change clusters.
4. Contradiction Detection: Flags opposing claims across systems (e.g. PR merged vs Jira blocked, approvals vs rejections).
"""

from __future__ import annotations

import uuid
from typing import Any, Dict, List, Optional, Set, Tuple
from pydantic import BaseModel, Field

from backend.evidence.models import Evidence
from backend.investigation.models import ContradictionRecord
from backend.release.models import (
    CIBuildStatus,
    CodeReviewStatus,
    FindingStatus,
    ReleaseCandidate,
    SecuritySeverity,
    WorkItemStatus,
)


class EvidenceValidationFailure(BaseModel):
    """Details on why a specific piece of evidence was rejected for this release."""
    evidence_id: str
    source_type: str
    rejection_reason: str
    details: Dict[str, Any] = Field(default_factory=dict)


class CorrelationCluster(BaseModel):
    """Unified cross-system correlation linking evidence for a specific component or change."""
    cluster_id: str = Field(default_factory=lambda: f"cluster-{uuid.uuid4().hex[:8]}")
    subject: str
    git_evidence_ids: List[str] = Field(default_factory=list)
    jira_evidence_ids: List[str] = Field(default_factory=list)
    ci_evidence_ids: List[str] = Field(default_factory=list)
    security_evidence_ids: List[str] = Field(default_factory=list)
    incident_evidence_ids: List[str] = Field(default_factory=list)
    summary: str = ""


class CorrelationResult(BaseModel):
    """Authoritative result of cross-system validation and correlation."""
    admitted_evidence: List[Evidence] = Field(default_factory=list)
    rejected_evidence: List[EvidenceValidationFailure] = Field(default_factory=list)
    clusters: List[CorrelationCluster] = Field(default_factory=list)
    contradictions: List[ContradictionRecord] = Field(default_factory=list)
    isolated_release_id: str


class CrossSystemCorrelator:
    """
    Deterministic correlation engine enforcing entity isolation, version/commit binding,
    temporal validity, and contradiction arbitration.
    """

    def __init__(self):
        pass

    def correlate_and_validate(
        self,
        candidate: ReleaseCandidate,
        raw_evidence: List[Evidence],
    ) -> CorrelationResult:
        """
        Evaluate raw evidence against the candidate release context.
        Filter out mismatched or stale items, build cross-system clusters, and detect contradictions.
        """
        admitted: List[Evidence] = []
        rejected: List[EvidenceValidationFailure] = []
        clusters: List[CorrelationCluster] = []
        contradictions: List[ContradictionRecord] = []

        # 1. Entity & Version Safety Gate
        for ev in raw_evidence:
            valid, reason, details = self._validate_evidence_binding(candidate, ev)
            if valid:
                admitted.append(ev)
            else:
                rejected.append(
                    EvidenceValidationFailure(
                        evidence_id=ev.evidence_id,
                        source_type=ev.source_type,
                        rejection_reason=reason,
                        details=details,
                    )
                )

        # 2. Build Cross-System Correlation Clusters
        cluster = CorrelationCluster(
            subject=f"{candidate.service_name}:{candidate.version}",
            summary=f"Unified release correlation for {candidate.service_name} at commit {candidate.commit[:10]}",
        )
        for ev in admitted:
            st = ev.source_type.lower()
            if "git" in st:
                cluster.git_evidence_ids.append(ev.evidence_id)
            elif "jira" in st or "linear" in st:
                cluster.jira_evidence_ids.append(ev.evidence_id)
            elif "ci" in st:
                cluster.ci_evidence_ids.append(ev.evidence_id)
            elif "security" in st:
                cluster.security_evidence_ids.append(ev.evidence_id)
            elif "incident" in st:
                cluster.incident_evidence_ids.append(ev.evidence_id)
        clusters.append(cluster)

        # 3. Cross-System Contradiction Detection
        contradictions.extend(self._detect_cross_system_contradictions(candidate, admitted))

        return CorrelationResult(
            admitted_evidence=admitted,
            rejected_evidence=rejected,
            clusters=clusters,
            contradictions=contradictions,
            isolated_release_id=candidate.release_id,
        )

    def _validate_evidence_binding(
        self,
        candidate: ReleaseCandidate,
        ev: Evidence,
    ) -> Tuple[bool, str, Dict[str, Any]]:
        """
        Enforces strict repository, commit, and temporal binding.
        """
        meta = ev.metadata or {}
        st = ev.source_type.lower()

        # Check explicit release ID mismatch if present
        ev_release_id = meta.get("release_id")
        if ev_release_id and ev_release_id != candidate.release_id:
            return False, "CROSS_RELEASE_LEAKAGE", {"expected_release": candidate.release_id, "found_release": ev_release_id}

        # Source Control (Git)
        if "git" in st:
            ev_repo = ev.source_id or meta.get("repository")
            if ev_repo and ev_repo != candidate.repository:
                return False, "FOREIGN_REPOSITORY", {"expected_repo": candidate.repository, "found_repo": ev_repo}

        # CI/CD Pipeline
        if "ci" in st:
            ev_repo = ev.source_id or meta.get("repository")
            if ev_repo and ev_repo != candidate.repository:
                return False, "FOREIGN_REPOSITORY", {"expected_repo": candidate.repository, "found_repo": ev_repo}

            ev_commit = meta.get("commit")
            if ev_commit and ev_commit != candidate.commit:
                return False, "STALE_COMMIT_EVIDENCE", {
                    "expected_commit": candidate.commit,
                    "found_commit": ev_commit,
                    "reason": "CI validation was executed against a different or older commit hash",
                }

        # Security Findings
        if "security" in st:
            ev_commit = meta.get("commit")
            if ev_commit and ev_commit != candidate.commit:
                return False, "STALE_COMMIT_EVIDENCE", {
                    "expected_commit": candidate.commit,
                    "found_commit": ev_commit,
                    "reason": "Security scan was executed against a different or older commit hash",
                }

        # Temporal validity check (e.g. evidence timestamp > candidate creation or older than allowed window)
        # If candidate metadata has a 'min_allowed_timestamp', enforce it
        min_ts = candidate.metadata.get("min_allowed_timestamp")
        if min_ts and ev.created_at and ev.created_at < min_ts:
            return False, "TEMPORAL_INVALIDITY", {"min_allowed": min_ts, "evidence_ts": ev.created_at}

        return True, "", {}

    def _detect_cross_system_contradictions(
        self,
        candidate: ReleaseCandidate,
        admitted_evidence: List[Evidence],
    ) -> List[ContradictionRecord]:
        """
        Cross-checks claims between Git, Jira, CI, and Security for irreconcilable oppositions.
        """
        contradictions: List[ContradictionRecord] = []

        git_evs = [e for e in admitted_evidence if "git" in e.source_type.lower()]
        jira_evs = [e for e in admitted_evidence if "jira" in e.source_type.lower()]
        ci_evs = [e for e in admitted_evidence if "ci" in e.source_type.lower()]
        sec_evs = [e for e in admitted_evidence if "security" in e.source_type.lower()]

        # Contradiction 1: Git PR Merged vs Jira Issue Blocked
        for gev in git_evs:
            g_meta = gev.metadata or {}
            is_merged = g_meta.get("is_merged") is True or "merged: true" in gev.content.lower()
            if is_merged:
                for jev in jira_evs:
                    j_meta = jev.metadata or {}
                    j_status = j_meta.get("status", "")
                    if j_status in ["BLOCKED", "REJECTED"] or "status: blocked" in jev.content.lower():
                        contradictions.append(
                            ContradictionRecord(
                                contradiction_id=f"contra-git-jira-{uuid.uuid4().hex[:6]}",
                                claim_a_evidence_id=gev.evidence_id,
                                claim_b_evidence_id=jev.evidence_id,
                                conflicting_subject=f"{candidate.service_name} change readiness",
                                basis=f"Git reports PR merged/approved ({gev.evidence_id}), but Jira reports issue {j_meta.get('item_id', 'work item')} is BLOCKED ({jev.evidence_id}).",
                                reconciled=False,
                            )
                        )

        # Contradiction 2: Work item / PR Approval vs Rejection
        for jev in jira_evs:
            j_meta = jev.metadata or {}
            approvals = j_meta.get("approvals", [])
            rejections = j_meta.get("rejections", [])
            if approvals and rejections:
                contradictions.append(
                    ContradictionRecord(
                        contradiction_id=f"contra-approval-rejection-{uuid.uuid4().hex[:6]}",
                        claim_a_evidence_id=jev.evidence_id,
                        claim_b_evidence_id=jev.evidence_id,
                        conflicting_subject=f"Governance approval for {j_meta.get('item_id', 'item')}",
                        basis=f"Conflicting governance records: item has both approvals ({', '.join(approvals)}) and rejections ({', '.join(rejections)}).",
                        reconciled=False,
                    )
                )

        # Contradiction 3: Security finding reported CRITICAL/HIGH active vs Exception claimed or contradictory scanner results
        # Check if scanner finding is marked ACTIVE but another evidence says exception accepted or superseded
        active_sec = [e for e in sec_evs if (e.metadata or {}).get("status") == "ACTIVE" and (e.metadata or {}).get("severity") in ["CRITICAL", "HIGH"]]
        for a_sec in active_sec:
            f_id = (a_sec.metadata or {}).get("finding_id", "")
            # Look for another evidence referencing this finding as EXCEPTION_ACCEPTED or FALSE_POSITIVE
            for o_sec in sec_evs:
                if o_sec.evidence_id != a_sec.evidence_id:
                    o_meta = o_sec.metadata or {}
                    if o_meta.get("finding_id") == f_id:
                        o_status = o_meta.get("status")
                        if o_status in ["EXCEPTION_ACCEPTED", "FALSE_POSITIVE", "RESOLVED"]:
                            contradictions.append(
                                ContradictionRecord(
                                    contradiction_id=f"contra-sec-{f_id}-{uuid.uuid4().hex[:6]}",
                                    claim_a_evidence_id=a_sec.evidence_id,
                                    claim_b_evidence_id=o_sec.evidence_id,
                                    conflicting_subject=f"Security finding {f_id} status",
                                    basis=f"Scanner reports active {o_meta.get('severity')} finding ({a_sec.evidence_id}), but governance/scan record ({o_sec.evidence_id}) claims status is {o_status}.",
                                    reconciled=False,
                                )
                            )

        # Contradiction 4: CI pipeline passed overall, but job failures or deployment validation failed
        for cev in ci_evs:
            c_meta = cev.metadata or {}
            if c_meta.get("status") == "PASSED" and c_meta.get("failed_tests", 0) > 0:
                contradictions.append(
                    ContradictionRecord(
                        contradiction_id=f"contra-ci-tests-{uuid.uuid4().hex[:6]}",
                        claim_a_evidence_id=cev.evidence_id,
                        claim_b_evidence_id=cev.evidence_id,
                        conflicting_subject=f"CI validation integrity for {c_meta.get('pipeline_id')}",
                        basis=f"Pipeline status is recorded as PASSED, but failed_tests count is {c_meta.get('failed_tests')}.",
                        reconciled=False,
                    )
                )

        return contradictions
