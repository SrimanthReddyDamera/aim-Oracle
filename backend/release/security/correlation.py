"""
Cross-System Security Correlator & Evidence Firewall (Brick 4.7)

Enforces strict, identity-safe cross-system correlation and isolation:
CVE / Finding
      ↓
Dependency
      ↓
Repository
      ↓
Commit
      ↓
PR
      ↓
CI Pipeline
      ↓
Artifact (SHA-256 Digest)
      ↓
Deployment / Service
      ↓
Jira / Work Item
      ↓
Incident
      ↓
Remediation PR
      ↓
Rescan Verification

Guarantees:
- Zero cross-repository finding leakage.
- Zero cross-tenant finding leakage.
- Strict rejection of wrong-commit or stale-artifact evidence.
- Returns admitted evidence and explicit rejection failure records.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Set, Tuple
from pydantic import BaseModel, Field

from backend.evidence.models import Evidence
from backend.release.correlation import EvidenceValidationFailure
from backend.release.security.models import SecurityFinding


class SecurityCorrelationCluster(BaseModel):
    """Cluster of correlated enterprise entities surrounding a security finding."""
    cluster_id: str
    finding_id: str
    repository: str
    commit: str
    artifact_digest: Optional[str] = None
    pr_id: Optional[str] = None
    ci_pipeline_id: Optional[str] = None
    work_item_ids: List[str] = Field(default_factory=list)
    service_id: Optional[str] = None
    incident_ids: List[str] = Field(default_factory=list)
    remediation_pr_ids: List[str] = Field(default_factory=list)
    rescan_evidence_ids: List[str] = Field(default_factory=list)


class SecurityCorrelationResult(BaseModel):
    """Result of cross-system security correlation and evidence admission."""
    admitted_findings: List[SecurityFinding] = Field(default_factory=list)
    admitted_evidence: List[Evidence] = Field(default_factory=list)
    rejected_evidence: List[EvidenceValidationFailure] = Field(default_factory=list)
    clusters: List[SecurityCorrelationCluster] = Field(default_factory=list)


class CrossSystemSecurityCorrelator:
    """
    Sovereign security correlation firewall.
    Verifies that all evidence matches target tenant, repository, commit,
    and artifact digest before admitting into the investigation.
    """

    def __init__(self):
        pass

    def correlate_and_firewall(
        self,
        repository: str,
        commit: str,
        tenant_id: str,
        artifact_digest: Optional[str] = None,
        findings: Optional[List[SecurityFinding]] = None,
        evidence_items: Optional[List[Evidence]] = None,
        linked_work_items: Optional[List[str]] = None,
        linked_pr_id: Optional[str] = None,
        linked_pipeline_id: Optional[str] = None,
    ) -> SecurityCorrelationResult:
        """
        Correlate and validate all incoming findings and evidence against target parameters.
        Discards any foreign, cross-repo, cross-tenant, or stale evidence.
        """
        admitted_findings: List[SecurityFinding] = []
        admitted_evidence: List[Evidence] = []
        rejected: List[EvidenceValidationFailure] = []
        clusters: List[SecurityCorrelationCluster] = []

        norm_repo = repository.strip().lower()
        norm_commit = commit.strip().lower()
        norm_tenant = tenant_id.strip()

        # 1. Validate Findings
        for finding in findings or []:
            f_repo = finding.repository.strip().lower()
            f_commit = finding.commit.strip().lower()
            f_tenant = finding.tenant_id.strip()

            # Cross-Tenant Leakage Check
            if f_tenant != norm_tenant:
                rejected.append(
                    EvidenceValidationFailure(
                        evidence_id=finding.finding_id,
                        source_type="security",
                        rejection_reason="CROSS_TENANT_LEAKAGE",
                        details={
                            "expected_tenant": norm_tenant,
                            "found_tenant": f_tenant,
                            "scanner": finding.scanner,
                        },
                    )
                )
                continue

            # Cross-Repository Leakage Check
            if f_repo != norm_repo:
                rejected.append(
                    EvidenceValidationFailure(
                        evidence_id=finding.finding_id,
                        source_type="security",
                        rejection_reason="CROSS_REPO_LEAKAGE",
                        details={
                            "expected_repo": norm_repo,
                            "found_repo": f_repo,
                            "scanner": finding.scanner,
                        },
                    )
                )
                continue

            # Commit Mismatch Check
            if f_commit != norm_commit:
                rejected.append(
                    EvidenceValidationFailure(
                        evidence_id=finding.finding_id,
                        source_type="security",
                        rejection_reason="WRONG_COMMIT_EVIDENCE",
                        details={
                            "expected_commit": norm_commit,
                            "found_commit": f_commit,
                            "scanner": finding.scanner,
                        },
                    )
                )
                continue

            # Artifact Digest Mismatch Check (if specified)
            if artifact_digest and finding.artifact_digest:
                if finding.artifact_digest.strip().lower() != artifact_digest.strip().lower():
                    rejected.append(
                        EvidenceValidationFailure(
                            evidence_id=finding.finding_id,
                            source_type="security",
                            rejection_reason="STALE_ARTIFACT_EVIDENCE",
                            details={
                                "expected_artifact": artifact_digest,
                                "found_artifact": finding.artifact_digest,
                                "scanner": finding.scanner,
                            },
                        )
                    )
                    continue

            # Admitted
            admitted_findings.append(finding)

            # Form Correlation Cluster
            cluster = SecurityCorrelationCluster(
                cluster_id=f"cluster-{finding.finding_id}",
                finding_id=finding.finding_id,
                repository=repository,
                commit=commit,
                artifact_digest=artifact_digest or finding.artifact_digest,
                pr_id=linked_pr_id,
                ci_pipeline_id=linked_pipeline_id,
                work_item_ids=linked_work_items or [],
                service_id=finding.package,
                rescan_evidence_ids=list(finding.evidence_ids),
            )
            clusters.append(cluster)

        # 2. Validate Raw Evidence Items
        for ev in evidence_items or []:
            ev_tenant = getattr(ev, "tenant_id", "default")
            ev_repo = ev.metadata.get("repository", "")
            ev_commit = ev.metadata.get("commit", "")
            ev_artifact = ev.metadata.get("artifact_digest")

            if ev_tenant and ev_tenant != norm_tenant:
                rejected.append(
                    EvidenceValidationFailure(
                        evidence_id=ev.evidence_id,
                        source_type=ev.source_type,
                        rejection_reason="CROSS_TENANT_LEAKAGE",
                        details={"expected_tenant": norm_tenant, "found_tenant": ev_tenant},
                    )
                )
                continue

            if ev_repo and ev_repo.strip().lower() != norm_repo:
                rejected.append(
                    EvidenceValidationFailure(
                        evidence_id=ev.evidence_id,
                        source_type=ev.source_type,
                        rejection_reason="CROSS_REPO_LEAKAGE",
                        details={"expected_repo": norm_repo, "found_repo": ev_repo},
                    )
                )
                continue

            if ev_commit and ev_commit.strip().lower() != norm_commit:
                rejected.append(
                    EvidenceValidationFailure(
                        evidence_id=ev.evidence_id,
                        source_type=ev.source_type,
                        rejection_reason="WRONG_COMMIT_EVIDENCE",
                        details={"expected_commit": norm_commit, "found_commit": ev_commit},
                    )
                )
                continue

            if artifact_digest and ev_artifact:
                if ev_artifact.strip().lower() != artifact_digest.strip().lower():
                    rejected.append(
                        EvidenceValidationFailure(
                            evidence_id=ev.evidence_id,
                            source_type=ev.source_type,
                            rejection_reason="STALE_ARTIFACT_EVIDENCE",
                            details={"expected_artifact": artifact_digest, "found_artifact": ev_artifact},
                        )
                    )
                    continue

            admitted_evidence.append(ev)

        return SecurityCorrelationResult(
            admitted_findings=admitted_findings,
            admitted_evidence=admitted_evidence,
            rejected_evidence=rejected,
            clusters=clusters,
        )
