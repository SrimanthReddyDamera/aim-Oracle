"""
Enterprise Release Providers & Evidence Normalization (Brick 4.0)

Implements clean provider abstractions and deterministic local implementations for:
1. GitReleaseProvider (Source control, PR reviews, commit metadata, rollback plans)
2. WorkManagementProvider (Jira / Linear issue tracking, blockers, production incidents)
3. CICDProvider (Automated test runs, build validation, commit-hash binding)
4. SecurityScanProvider (SAST, SCA, Secrets, DAST vulnerability findings)
5. InMemoryReleaseDataProvider (Unified local test fixture conforming to EvidenceProvider)
"""

from __future__ import annotations

import hashlib
import time
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Set, Tuple

from backend.evidence.models import Evidence
from backend.release.models import (
    CIBuildStatus,
    CIPipelineRun,
    CodeReviewStatus,
    FindingStatus,
    PullRequestReview,
    ReleaseCandidate,
    SecurityCategory,
    SecurityFinding,
    SecuritySeverity,
    WorkItem,
    WorkItemStatus,
)
from backend.retrieval.provider import EvidenceProvider, ProviderCapability, ProviderSearchResult


def _create_evidence(
    evidence_id: str,
    source_id: str,
    source_type: str,
    content: str,
    metadata: Dict[str, Any],
    timestamp: str = "2026-10-25T10:00:00Z",
) -> Evidence:
    """Helper to construct canonical normalized Evidence with byte offsets and SHA-256 hash."""
    encoded = content.encode("utf-8")
    content_hash = hashlib.sha256(encoded).hexdigest()
    return Evidence(
        evidence_id=evidence_id,
        source_id=source_id,
        source_type=source_type,
        uri=f"{source_type}://{source_id}/{evidence_id}",
        content=content,
        content_hash=content_hash,
        source_path=f"/providers/{source_type}/{evidence_id}.json",
        chunk_index=0,
        start_offset=0,
        end_offset=len(encoded),
        metadata=metadata,
        created_at=timestamp,
        confidence=0.98,
    )


# -----------------------------------------------------------------------------
# 1. ABSTRACT PROVIDERS
# -----------------------------------------------------------------------------

class BaseReleaseDataProvider(ABC):
    """Abstract contract for enterprise release sensor providers."""

    @abstractmethod
    def fetch_evidence_for_release(self, candidate: ReleaseCandidate) -> List[Evidence]:
        raise NotImplementedError


class GitReleaseProvider(BaseReleaseDataProvider):
    """Contract for source control repository evidence."""

    @abstractmethod
    def get_pull_request(self, repository: str, pr_id: str) -> Optional[PullRequestReview]:
        raise NotImplementedError

    @abstractmethod
    def get_commit_reviews(self, repository: str, commit: str) -> List[PullRequestReview]:
        raise NotImplementedError


class WorkManagementProvider(BaseReleaseDataProvider):
    """Contract for Jira, Linear, and incident management evidence."""

    @abstractmethod
    def get_work_item(self, item_id: str) -> Optional[WorkItem]:
        raise NotImplementedError

    @abstractmethod
    def get_active_incidents_for_service(self, service_name: str) -> List[WorkItem]:
        raise NotImplementedError


class CICDProvider(BaseReleaseDataProvider):
    """Contract for CI/CD build and test validation evidence."""

    @abstractmethod
    def get_pipeline_runs_for_commit(self, repository: str, commit: str) -> List[CIPipelineRun]:
        raise NotImplementedError


class SecurityScanProvider(BaseReleaseDataProvider):
    """Contract for SAST, SCA, Secrets, and container vulnerability findings."""

    @abstractmethod
    def get_findings_for_commit(self, repository: str, commit: str) -> List[SecurityFinding]:
        raise NotImplementedError


# -----------------------------------------------------------------------------
# 2. IN-MEMORY DETERMINISTIC PROVIDER (ENTERPRISE TEST FIXTURE)
# -----------------------------------------------------------------------------

class InMemoryReleaseDataProvider(
    GitReleaseProvider,
    WorkManagementProvider,
    CICDProvider,
    SecurityScanProvider,
    EvidenceProvider,
):
    """
    Unified, deterministic, in-memory implementation of enterprise release providers.
    Supports complete simulation of Git, Jira, CI/CD, and Security datasets,
    fault injection (timeouts, outages), and direct integration into InvestigationController.
    """

    def __init__(self, provider_id: str = "in_memory_release_provider"):
        self._provider_id = provider_id
        # Registries
        self.pull_requests: Dict[str, PullRequestReview] = {}
        self.work_items: Dict[str, WorkItem] = {}
        self.pipeline_runs: Dict[str, List[CIPipelineRun]] = {}  # commit -> runs
        self.security_findings: Dict[str, List[SecurityFinding]] = {}  # commit -> findings
        self.active_incidents: Dict[str, List[WorkItem]] = {}  # service_name -> incidents
        
        # Outage and failure simulation flags
        self.outages: Set[str] = set()  # "git", "jira", "ci", "security"
        self.timeouts: Set[str] = set()

    @property
    def provider_id(self) -> str:
        return self._provider_id

    # -------------------------------------------------------------------------
    # DATA SEEDING HELPERS
    # -------------------------------------------------------------------------

    def add_pull_request(self, pr: PullRequestReview) -> None:
        self.pull_requests[pr.pr_id] = pr

    def add_work_item(self, item: WorkItem) -> None:
        self.work_items[item.item_id] = item
        if item.is_incident:
            for s in item.linked_releases:
                self.active_incidents.setdefault(s, []).append(item)

    def add_pipeline_run(self, run: CIPipelineRun) -> None:
        self.pipeline_runs.setdefault(run.commit, []).append(run)

    # Alias used by Brick 4.7 security intelligence tests
    def add_ci_pipeline(self, run: CIPipelineRun) -> None:
        self.add_pipeline_run(run)

    def add_security_finding(self, finding: SecurityFinding) -> None:
        self.security_findings.setdefault(finding.commit, []).append(finding)

    def simulate_outage(self, provider_type: str) -> None:
        self.outages.add(provider_type.lower())

    def simulate_timeout(self, provider_type: str) -> None:
        self.timeouts.add(provider_type.lower())

    def clear_failures(self) -> None:
        self.outages.clear()
        self.timeouts.clear()

    # -------------------------------------------------------------------------
    # PROVIDER CONTRACT IMPLEMENTATIONS
    # -------------------------------------------------------------------------

    def get_pull_request(self, repository: str, pr_id: str) -> Optional[PullRequestReview]:
        if "git" in self.outages or "git" in self.timeouts:
            return None
        pr = self.pull_requests.get(pr_id)
        if pr and pr.repository == repository:
            return pr
        return None

    def get_commit_reviews(self, repository: str, commit: str) -> List[PullRequestReview]:
        if "git" in self.outages or "git" in self.timeouts:
            return []
        return [pr for pr in self.pull_requests.values() if pr.repository == repository and pr.head_commit == commit]

    def get_work_item(self, item_id: str) -> Optional[WorkItem]:
        if "jira" in self.outages or "jira" in self.timeouts:
            return None
        return self.work_items.get(item_id)

    def get_active_incidents_for_service(self, service_name: str) -> List[WorkItem]:
        if "jira" in self.outages or "jira" in self.timeouts:
            return []
        return [item for item in self.work_items.values() if item.is_incident and item.status != WorkItemStatus.DONE and service_name in item.linked_releases]

    def get_pipeline_runs_for_commit(self, repository: str, commit: str) -> List[CIPipelineRun]:
        if "ci" in self.outages or "ci" in self.timeouts:
            return []
        runs = self.pipeline_runs.get(commit, [])
        return [r for r in runs if r.repository == repository]

    def get_findings_for_commit(self, repository: str, commit: str) -> List[SecurityFinding]:
        if "security" in self.outages or "security" in self.timeouts:
            return []
        findings = self.security_findings.get(commit, [])
        return [f for f in findings if f.repository == repository]

    # -------------------------------------------------------------------------
    # NORMALIZATION INTO CANONICAL ORACLE EVIDENCE
    # -------------------------------------------------------------------------

    def fetch_evidence_for_release(self, candidate: ReleaseCandidate) -> List[Evidence]:
        """
        Aggregate and normalize all available provider data for candidate into Evidence items.
        """
        evidence_list: List[Evidence] = []

        # 1. Git PR Evidence
        if "git" not in self.outages and "git" not in self.timeouts:
            prs = []
            if candidate.pull_request_id and candidate.pull_request_id in self.pull_requests:
                prs.append(self.pull_requests[candidate.pull_request_id])
            else:
                prs.extend(self.get_commit_reviews(candidate.repository, candidate.commit))

            for pr in prs:
                rb_clause = "Rollback procedure is verified and documented." if pr.rollback_procedure_documented else "No rollback procedure documented."
                content = (
                    f"Pull Request {pr.pr_id} on {pr.repository} for commit {pr.head_commit[:10]}:\n"
                    f"Code Review Status: {pr.status.value}.\n"
                    f"Reviewers: {', '.join(pr.reviewers) if pr.reviewers else 'None'}.\n"
                    f"Approvers: {', '.join(pr.approvers) if pr.approvers else 'None'}.\n"
                    f"Merged: {pr.is_merged}.\n"
                    f"{rb_clause}"
                )
                evidence_list.append(
                    _create_evidence(
                        evidence_id=f"GIT-PR-{pr.pr_id}",
                        source_id=pr.repository,
                        source_type="git",
                        content=content,
                    metadata={
                        "pr_id": pr.pr_id,
                        "status": pr.status.value,
                        "commit": pr.head_commit,
                        "approvers": pr.approvers,
                        "is_merged": pr.is_merged,
                    },
                    timestamp=pr.timestamp or candidate.created_at,
                )
            )

        # 2. Jira / Linear Work Items
        if "jira" not in self.outages and "jira" not in self.timeouts:
            for item_id in candidate.linked_work_item_ids:
                item = self.get_work_item(item_id)
                if item:
                    app_clause = f"Approvals: {', '.join(item.approvals)}." if item.approvals else "No approvals recorded."
                    rej_clause = f"Rejections: {', '.join(item.rejections)}." if item.rejections else ""
                    content = (
                        f"Work Item {item.item_id}: {item.title}.\n"
                        f"Status: {item.status.value}. Priority: {item.priority}.\n"
                        f"Blocking: {item.is_blocking}. Incident: {item.is_incident}.\n"
                        f"Owner: {item.owner}.\n"
                        f"{app_clause} {rej_clause}".strip()
                    )
                    evidence_list.append(
                        _create_evidence(
                            evidence_id=f"WORK-{item.item_id}",
                            source_id="jira.corp.internal",
                            source_type="jira",
                            content=content,
                            metadata={
                                "item_id": item.item_id,
                                "status": item.status.value,
                                "priority": item.priority,
                                "is_blocking": item.is_blocking,
                                "approvals": item.approvals,
                                "rejections": item.rejections,
                            },
                            timestamp=item.timestamp or candidate.created_at,
                        )
                    )

            # Active incidents for service
            incidents = self.get_active_incidents_for_service(candidate.service_name)
            for inc in incidents:
                content = (
                    f"ACTIVE INCIDENT {inc.item_id}: {inc.title}.\n"
                    f"Service Affected: {candidate.service_name}.\n"
                    f"Status: {inc.status.value}. Priority: {inc.priority}."
                )
                evidence_list.append(
                    _create_evidence(
                        evidence_id=f"INCIDENT-{inc.item_id}",
                        source_id="incident.corp.internal",
                        source_type="incident",
                        content=content,
                        metadata={"incident_id": inc.item_id, "priority": inc.priority, "status": inc.status.value},
                        timestamp=inc.timestamp or candidate.created_at,
                    )
                )

        # 3. CI/CD Pipeline Runs (gather all repository pipeline runs to detect stale commits)
        if "ci" not in self.outages and "ci" not in self.timeouts:
            repo_runs: List[CIPipelineRun] = []
            for run_list in self.pipeline_runs.values():
                for r in run_list:
                    if r.repository == candidate.repository:
                        repo_runs.append(r)

            for run in repo_runs:
                failed_str = f"Failed jobs: {', '.join(run.failed_jobs)}" if run.failed_jobs else "All jobs succeeded."
                content = (
                    f"CI Pipeline {run.pipeline_id} for {run.repository} at commit {run.commit[:10]}:\n"
                    f"Build & Test Status: {run.status.value}.\n"
                    f"Tests: {run.passed_tests}/{run.total_tests} passed. {run.failed_tests} failed.\n"
                    f"{failed_str}"
                )
                evidence_list.append(
                    _create_evidence(
                        evidence_id=f"CI-{run.pipeline_id}",
                        source_id=run.repository,
                        source_type="ci",
                        content=content,
                        metadata={"pipeline_id": run.pipeline_id, "commit": run.commit, "status": run.status.value, "failed_tests": run.failed_tests},
                        timestamp=run.timestamp or candidate.created_at,
                    )
                )

        # 4. Security Findings (gather all repository findings to enable cross-scan and stale commit analysis)
        if "security" not in self.outages and "security" not in self.timeouts:
            repo_findings: List[SecurityFinding] = []
            for flist in self.security_findings.values():
                for f in flist:
                    if f.repository == candidate.repository:
                        repo_findings.append(f)

            for f in repo_findings:
                pkg_clause = f"Package {f.package} ({f.current_version}) -> Fixed in: {f.fixed_version or 'None'}." if f.package else ""
                reach_clause = "Vulnerable code path is REACHABLE." if f.is_reachable else "Code path is UNREACHABLE."
                cve_clause = f"Vulnerability: {f.cve} (CVSS {f.cvss or 'N/A'}, CWE {f.cwe or 'N/A'})." if f.cve else ""
                content = (
                    f"Security Finding {f.finding_id} from {f.scanner} on {f.repository} commit {f.commit[:10]}:\n"
                    f"Category: {f.category.value}. Severity: {f.severity.value}. Status: {f.status.value}.\n"
                    f"{cve_clause}\n"
                    f"{pkg_clause}\n"
                    f"{reach_clause}\n"
                    f"Description: {f.description}.\n"
                    f"Remediation: {f.remediation_guidance}."
                )
                evidence_list.append(
                    _create_evidence(
                        evidence_id=f"SEC-{f.scanner}-{f.finding_id}",
                        source_id=f.scanner,
                        source_type="security",
                        content=content,
                        metadata={
                            "finding_id": f.finding_id,
                            "scanner": f.scanner,
                            "category": f.category.value,
                            "severity": f.severity.value,
                            "status": f.status.value,
                            "cve": f.cve,
                            "commit": f.commit,
                            "package": f.package,
                            "current_version": f.current_version,
                            "fixed_version": f.fixed_version,
                            "is_reachable": f.is_reachable,
                            "is_exploitable": f.is_exploitable_in_context,
                        },
                        timestamp=f.last_seen or candidate.created_at,
                    )
                )

        return evidence_list

    # -------------------------------------------------------------------------
    # EvidenceProvider INTERFACE IMPLEMENTATION FOR CONTROLLER
    # -------------------------------------------------------------------------

    @property
    def capabilities(self) -> Set[ProviderCapability]:
        return {
            ProviderCapability.LEXICAL_SEARCH,
            ProviderCapability.STRUCTURED_FILTER,
            ProviderCapability.ENTITY_LOOKUP,
            ProviderCapability.LOCAL_CACHE,
        }

    def health_check(self) -> bool:
        return len(self.outages) == 0

    def search(
        self,
        query: str,
        k: int = 5,
        filters: Optional[Dict[str, Any]] = None,
    ) -> Tuple[List[Tuple[Evidence, float]], float]:
        """Execute search query returning ([(Evidence, score)], elapsed_latency_ms)."""
        start = time.time()
        norm_q = query.strip().lower()
        results: List[Tuple[Evidence, float]] = []

        all_evidence: List[Evidence] = []
        for pr in self.pull_requests.values():
            all_evidence.append(_create_evidence(f"GIT-PR-{pr.pr_id}", pr.repository, "git", f"PR {pr.pr_id}: {pr.status.value} for {pr.head_commit}", {}))
        for item in self.work_items.values():
            all_evidence.append(_create_evidence(f"WORK-{item.item_id}", "jira", "jira", f"Issue {item.item_id}: {item.title} {item.status.value}", {}))
        for runs in self.pipeline_runs.values():
            for r in runs:
                all_evidence.append(_create_evidence(f"CI-{r.pipeline_id}", r.repository, "ci", f"CI {r.pipeline_id}: {r.status.value} for {r.commit}", {}))
        for flist in self.security_findings.values():
            for f in flist:
                all_evidence.append(_create_evidence(f"SEC-{f.finding_id}", f.scanner, "security", f"Finding {f.finding_id}: {f.severity.value} {f.description}", {}))

        for ev in all_evidence:
            if any(term in ev.content.lower() for term in norm_q.split()):
                results.append((ev, 1.0))
                if len(results) >= k:
                    break

        elapsed_ms = (time.time() - start) * 1000.0
        return results, elapsed_ms

    def search_provider(
        self,
        query: str,
        k: int = 4,
        filters: Optional[Dict[str, Any]] = None,
    ) -> List[ProviderSearchResult]:
        """Execute search returning normalized ProviderSearchResult instances."""
        res, _ = self.search(query, k=k, filters=filters)
        return [
            ProviderSearchResult(
                evidence_id=ev.evidence_id,
                source_type=ev.source_type,
                source_id=ev.source_id,
                content=ev.content,
                score=score,
                metadata=ev.metadata,
                evidence=ev,
            )
            for ev, score in res
        ]
