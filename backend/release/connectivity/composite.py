"""
Composite Enterprise Release Provider (Bricks 4.1 & 4.2)

Combines production GitHub, Jira, GitHub Actions, and Security providers into a unified
facade conforming to BaseReleaseDataProvider and EvidenceProvider.
Executes independent provider queries concurrently with circuit breaking, failure isolation,
and structured operational telemetry.
"""

from __future__ import annotations

import concurrent.futures
import time
from typing import Any, Dict, List, Optional, Set, Tuple

from backend.evidence.models import Evidence
from backend.release.connectivity.github import GitHubReleaseProvider
from backend.release.connectivity.github_actions import GitHubActionsCICDProvider
from backend.release.connectivity.jira import JiraWorkManagementProvider
from backend.release.connectivity.resilience import ProviderNetworkError
from backend.release.connectivity.security import SemgrepSecurityProvider
from backend.release.connectivity.telemetry import InvestigationTelemetryLedger
from backend.release.models import (
    CIPipelineRun,
    PullRequestReview,
    ReleaseCandidate,
    SecurityFinding,
    WorkItem,
)
from backend.release.providers import (
    BaseReleaseDataProvider,
    CICDProvider,
    GitReleaseProvider,
    SecurityScanProvider,
    WorkManagementProvider,
)
from backend.retrieval.provider import EvidenceProvider, ProviderCapability, ProviderSearchResult


class EnterpriseReleaseDataProvider(
    GitReleaseProvider,
    WorkManagementProvider,
    CICDProvider,
    SecurityScanProvider,
    EvidenceProvider,
):
    """
    Unified composite provider orchestrating real external systems.
    Concurrently fetches and aggregates evidence from GitHub, Jira, GitHub Actions, and Security scanners.
    Instruments each call with operational telemetry and circuit-breaker isolation.
    """

    def __init__(
        self,
        git_provider: Optional[GitReleaseProvider] = None,
        work_provider: Optional[WorkManagementProvider] = None,
        ci_provider: Optional[CICDProvider] = None,
        security_provider: Optional[SecurityScanProvider] = None,
        provider_id: str = "enterprise_release_provider",
        telemetry_ledger: Optional[InvestigationTelemetryLedger] = None,
    ):
        self._provider_id = provider_id
        self.git_provider = git_provider or GitHubReleaseProvider()
        self.work_provider = work_provider or JiraWorkManagementProvider()
        self.ci_provider = ci_provider or GitHubActionsCICDProvider()
        self.security_provider = security_provider or SemgrepSecurityProvider()
        self.telemetry_ledger = telemetry_ledger or InvestigationTelemetryLedger()

        # Track any provider outage or failure encountered during operations
        self.outages: Set[str] = set()
        self.timeouts: Set[str] = set()

    @property
    def provider_id(self) -> str:
        return self._provider_id

    def _get_circuit_state(self, provider_obj: Any) -> str:
        """Helper to safely inspect provider circuit breaker state."""
        client = getattr(provider_obj, "client", None)
        if client and hasattr(client, "circuit_breaker"):
            return client.circuit_breaker.state.value
        return "CLOSED"

    # -------------------------------------------------------------------------
    # DELEGATED SENSOR METHODS
    # -------------------------------------------------------------------------

    def get_pull_request(self, repository: str, pr_id: str) -> Optional[PullRequestReview]:
        try:
            return self.git_provider.get_pull_request(repository, pr_id)
        except ProviderNetworkError:
            self.outages.add("git")
            return None

    def get_commit_reviews(self, repository: str, commit: str) -> List[PullRequestReview]:
        try:
            return self.git_provider.get_commit_reviews(repository, commit)
        except ProviderNetworkError:
            self.outages.add("git")
            return []

    def get_work_item(self, item_id: str) -> Optional[WorkItem]:
        try:
            return self.work_provider.get_work_item(item_id)
        except ProviderNetworkError:
            self.outages.add("jira")
            return None

    def get_active_incidents_for_service(self, service_name: str) -> List[WorkItem]:
        try:
            return self.work_provider.get_active_incidents_for_service(service_name)
        except ProviderNetworkError:
            self.outages.add("jira")
            return []

    def get_pipeline_runs_for_commit(self, repository: str, commit: str) -> List[CIPipelineRun]:
        try:
            return self.ci_provider.get_pipeline_runs_for_commit(repository, commit)
        except ProviderNetworkError:
            self.outages.add("ci")
            return []

    def get_findings_for_commit(self, repository: str, commit: str) -> List[SecurityFinding]:
        try:
            return self.security_provider.get_findings_for_commit(repository, commit)
        except ProviderNetworkError:
            self.outages.add("security")
            return []

    # -------------------------------------------------------------------------
    # CONCURRENT EVIDENCE AGGREGATION WITH OPERATIONAL TELEMETRY
    # -------------------------------------------------------------------------

    def fetch_evidence_for_release(self, candidate: ReleaseCandidate) -> List[Evidence]:
        """
        Concurrently query all connected enterprise providers and collect normalized Evidence.
        Isolates failures so a single provider failure does not crash the entire investigation.
        Records structured operational telemetry for each provider operation.
        """
        self.outages.clear()
        self.timeouts.clear()
        aggregated_evidence: List[Evidence] = []

        # Set ledger release_id if not already set
        self.telemetry_ledger.release_id = candidate.release_id

        def fetch_git():
            c_state = self._get_circuit_state(self.git_provider)
            try:
                with self.telemetry_ledger.record_operation("git", "fetch_evidence_for_release", circuit_state=c_state) as ctx:
                    ev_list = self.git_provider.fetch_evidence_for_release(candidate)
                    ctx["evidence_count"] = len(ev_list)
                    return "git", ev_list, None
            except Exception as e:
                return "git", [], e

        def fetch_work():
            c_state = self._get_circuit_state(self.work_provider)
            try:
                with self.telemetry_ledger.record_operation("jira", "fetch_evidence_for_release", circuit_state=c_state) as ctx:
                    ev_list = self.work_provider.fetch_evidence_for_release(candidate)
                    ctx["evidence_count"] = len(ev_list)
                    return "jira", ev_list, None
            except Exception as e:
                return "jira", [], e

        def fetch_ci():
            c_state = self._get_circuit_state(self.ci_provider)
            try:
                with self.telemetry_ledger.record_operation("ci", "fetch_evidence_for_release", circuit_state=c_state) as ctx:
                    ev_list = self.ci_provider.fetch_evidence_for_release(candidate)
                    ctx["evidence_count"] = len(ev_list)
                    return "ci", ev_list, None
            except Exception as e:
                return "ci", [], e

        def fetch_security():
            c_state = self._get_circuit_state(self.security_provider)
            try:
                with self.telemetry_ledger.record_operation("security", "fetch_evidence_for_release", circuit_state=c_state) as ctx:
                    ev_list = self.security_provider.fetch_evidence_for_release(candidate)
                    ctx["evidence_count"] = len(ev_list)
                    return "security", ev_list, None
            except Exception as e:
                return "security", [], e

        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
            futures = [
                executor.submit(fetch_git),
                executor.submit(fetch_work),
                executor.submit(fetch_ci),
                executor.submit(fetch_security),
            ]
            for fut in concurrent.futures.as_completed(futures):
                provider_name, ev_list, err = fut.result()
                if err is not None:
                    self.outages.add(provider_name)
                else:
                    aggregated_evidence.extend(ev_list)

        return aggregated_evidence

    # -------------------------------------------------------------------------
    # EvidenceProvider IMPLEMENTATION
    # -------------------------------------------------------------------------

    @property
    def capabilities(self) -> Set[ProviderCapability]:
        return {
            ProviderCapability.LEXICAL_SEARCH,
            ProviderCapability.STRUCTURED_FILTER,
            ProviderCapability.ENTITY_LOOKUP,
            ProviderCapability.NETWORK_REMOTE,
        }

    def health_check(self) -> bool:
        return len(self.outages) == 0

    def search(
        self,
        query: str,
        k: int = 5,
        filters: Optional[Dict[str, Any]] = None,
    ) -> Tuple[List[Tuple[Evidence, float]], float]:
        start = time.time()
        elapsed_ms = (time.time() - start) * 1000.0
        return [], elapsed_ms

    def search_provider(
        self,
        query: str,
        k: int = 4,
        filters: Optional[Dict[str, Any]] = None,
    ) -> List[ProviderSearchResult]:
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
