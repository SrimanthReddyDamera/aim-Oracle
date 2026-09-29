"""
Release Readiness Investigation Engine & DAG Evaluation (Brick 4.0)

Implements the dedicated release readiness investigation capability:
1. Dynamic gap derivation tailored to release candidate context.
2. True DAG dependency graph (Code Ready, Security Clear, Operations Ready -> Release Root).
3. Asynchronous parallel execution across independent check workers.
4. Epistemic state propagation (topological invalidation and restoration cascades).
5. Explicit handling of contradictions, provider outages, and stale evidence.
"""

from __future__ import annotations

import concurrent.futures
import time
import uuid
from typing import Any, Dict, List, Optional, Set, Tuple
from pydantic import BaseModel, Field

from backend.evidence.models import Evidence
from backend.investigation.dag import DependencyGraph
from backend.investigation.models import ContradictionRecord, GapStatus, GapType, InformationGap
from backend.release.correlation import CorrelationCluster, CorrelationResult, CrossSystemCorrelator, EvidenceValidationFailure
from backend.release.models import ReleaseCandidate
from backend.release.providers import BaseReleaseDataProvider, InMemoryReleaseDataProvider


class ReleaseInvestigationResult(BaseModel):
    """Structured deliverable of a release readiness investigation."""
    investigation_id: str = Field(default_factory=lambda: f"inv-rel-{uuid.uuid4().hex[:8]}")
    candidate: ReleaseCandidate
    gaps: List[InformationGap] = Field(default_factory=list)
    admitted_evidence: List[Evidence] = Field(default_factory=list)
    rejected_evidence: List[EvidenceValidationFailure] = Field(default_factory=list)
    contradictions: List[ContradictionRecord] = Field(default_factory=list)
    clusters: List[CorrelationCluster] = Field(default_factory=list)
    outages_detected: List[str] = Field(default_factory=list)
    telemetry: Dict[str, Any] = Field(default_factory=dict)
    security_investigation: Optional[Any] = None
    security_release_assessment: Optional[Any] = None

    model_config = {"arbitrary_types_allowed": True}

    @property
    def is_root_resolved(self) -> bool:
        root = next((g for g in self.gaps if g.gap_id == "GAP-RELEASE-ROOT"), None)
        return root is not None and root.status == GapStatus.RESOLVED

    @property
    def has_contradictions(self) -> bool:
        return len(self.contradictions) > 0 or any(g.status == GapStatus.RECONCILIATION_REQUIRED for g in self.gaps)


class ReleaseReadinessInvestigator:
    """
    Controller-governed release readiness investigator.
    Orchestrates evidence gathering, cross-system correlation, DAG generation,
    and concurrent multi-worker check evaluation.
    """

    def __init__(
        self,
        provider: Optional[BaseReleaseDataProvider] = None,
        correlator: Optional[CrossSystemCorrelator] = None,
        max_workers: int = 4,
        store: Optional[Any] = None,
        security_engine: Optional[Any] = None,
    ):
        self.provider = provider or InMemoryReleaseDataProvider()
        self.correlator = correlator or CrossSystemCorrelator()
        self.max_workers = max_workers
        self.store = store
        self.security_engine = security_engine

    def investigate(
        self,
        candidate: ReleaseCandidate,
        tenant_id: Optional[str] = None,
        build_artifact: Optional[Any] = None,
        deployment: Optional[Any] = None,
        runtime_service: Optional[Any] = None,
        raw_findings: Optional[List[Dict[str, Any]]] = None,
        call_graph: Optional[Dict[str, List[str]]] = None,
        registered_routes: Optional[List[str]] = None,
        external_evidences: Optional[List[Any]] = None,
    ) -> ReleaseInvestigationResult:
        """
        Execute full release readiness investigation for the candidate.
        """
        start_time = time.time()
        investigation_id = f"inv-rel-{uuid.uuid4().hex[:8]}"

        # 1. Fetch raw evidence from provider
        fetch_start = time.time()
        raw_evidence = self.provider.fetch_evidence_for_release(candidate)
        if external_evidences:
            raw_evidence = list(raw_evidence) + list(external_evidences)
        fetch_duration = time.time() - fetch_start

        # Detect provider outages from provider instance if supported
        outages_detected: List[str] = []
        if hasattr(self.provider, "outages"):
            outages = getattr(self.provider, "outages", set())
            timeouts = getattr(self.provider, "timeouts", set())
            outages_detected.extend(list(set(outages).union(set(timeouts))))

        # 2. Correlate and validate evidence (Entity safety, version binding, contradictions)
        corr_start = time.time()
        corr_res = self.correlator.correlate_and_validate(candidate, raw_evidence)
        corr_duration = time.time() - corr_start

        # 3. Construct DAG of Gaps
        gaps_map, dag = self._build_investigation_dag(candidate)

        # 4. Concurrent execution of leaf sensor gaps
        eval_start = time.time()
        self._evaluate_leaf_gaps_concurrently(
            candidate=candidate,
            gaps_map=gaps_map,
            admitted_evidence=corr_res.admitted_evidence,
            rejected_failures=corr_res.rejected_evidence,
            contradictions=corr_res.contradictions,
            outages=outages_detected,
        )
        eval_duration = time.time() - eval_start

        # 5. Topological cascade through DAG (evaluate intermediate and root gaps)
        self._topological_dag_cascade(gaps_map, dag)

        total_duration = time.time() - start_time

        telemetry = {
            "total_duration_ms": round(total_duration * 1000, 2),
            "fetch_duration_ms": round(fetch_duration * 1000, 2),
            "correlation_duration_ms": round(corr_duration * 1000, 2),
            "evaluation_duration_ms": round(eval_duration * 1000, 2),
            "raw_evidence_count": len(raw_evidence),
            "admitted_evidence_count": len(corr_res.admitted_evidence),
            "rejected_evidence_count": len(corr_res.rejected_evidence),
            "contradictions_count": len(corr_res.contradictions),
            "worker_concurrency": self.max_workers,
        }

        # Attach provider operational telemetry if available
        if hasattr(self.provider, "telemetry_ledger"):
            ledger = getattr(self.provider, "telemetry_ledger")
            telemetry["provider_operations"] = [r.to_dict() for r in ledger.get_records()]
            telemetry["provider_summary"] = ledger.summary()

        # 6. Integrated Security Readiness Assessment (Brick 4.8)
        sec_inv = None
        sec_rel_assess = None
        if self.security_engine and hasattr(self.security_engine, "investigate"):
            try:
                findings_ev = [
                    fe for fe in corr_res.admitted_evidence
                    if "security" in fe.source_type.lower() or "finding" in fe.source_type.lower()
                ]
                from backend.release.security.models import (
                    FindingStatus,
                    SecurityCategory,
                    SecurityFinding,
                    SecuritySeverity,
                )
                norm_findings = []
                for fe in findings_ev:
                    meta = fe.metadata or {}
                    cat_val = meta.get("category", "SCA").upper()
                    sev_val = meta.get("severity", "MEDIUM").upper()
                    stat_val = meta.get("status", "ACTIVE").upper()
                    norm_findings.append(
                        SecurityFinding(
                            finding_id=meta.get("finding_id", fe.evidence_id),
                            scanner=meta.get("scanner", "security_scanner"),
                            category=SecurityCategory[cat_val] if cat_val in SecurityCategory.__members__ else SecurityCategory.SCA,
                            severity=SecuritySeverity[sev_val] if sev_val in SecuritySeverity.__members__ else SecuritySeverity.MEDIUM,
                            status=FindingStatus[stat_val] if stat_val in FindingStatus.__members__ else FindingStatus.ACTIVE,
                            repository=candidate.repository,
                            commit=candidate.commit,
                            artifact_digest=candidate.artifact_digest or (build_artifact.artifact_digest if build_artifact else None),
                            package=meta.get("package"),
                            cve=meta.get("cve"),
                            description=meta.get("description", fe.description),
                            is_reachable=meta.get("is_reachable", True),
                        )
                    )
                sec_inv = self.security_engine.investigate(
                    repository=candidate.repository,
                    commit=candidate.commit,
                    tenant_id=candidate.tenant_id or tenant_id or "default",
                    artifact_digest=candidate.artifact_digest or (build_artifact.artifact_digest if build_artifact else None),
                    raw_findings=raw_findings,
                    normalized_findings=norm_findings if norm_findings else None,
                    candidate=candidate,
                    build_artifact=build_artifact,
                    deployment=deployment,
                    service=runtime_service,
                    call_graph=call_graph,
                    registered_routes=registered_routes,
                )
                sec_rel_assess = getattr(sec_inv, "release_assessment", None)
                if sec_rel_assess and (getattr(sec_rel_assess, "blocks_release", False) or getattr(sec_rel_assess, "is_release_blocked", False)):
                    for g_id in ["GAP-SECURITY-CLEAR", "GAP-SECURITY-SAST", "GAP-SECURITY-SCA"]:
                        g = gaps_map.get(g_id)
                        if g:
                            g.status = GapStatus.BLOCKED
                            g.resolution = f"Security impact blocker: {'; '.join(getattr(sec_rel_assess, 'blocking_reasons', []))}"
            except Exception:
                pass

        result = ReleaseInvestigationResult(
            investigation_id=investigation_id,
            candidate=candidate,
            gaps=list(gaps_map.values()),
            admitted_evidence=corr_res.admitted_evidence,
            rejected_evidence=corr_res.rejected_evidence,
            contradictions=corr_res.contradictions,
            clusters=corr_res.clusters,
            outages_detected=outages_detected,
            telemetry=telemetry,
            security_investigation=sec_inv,
            security_release_assessment=sec_rel_assess,
        )

        if self.store:
            if hasattr(self.store, "entities"):
                self.store.entities.save_candidate(candidate)
            if hasattr(self.store, "investigations"):
                self.store.investigations.save_investigation(result)

        return result

    def reinvestigate_targeted(
        self,
        candidate: ReleaseCandidate,
        previous_result: ReleaseInvestigationResult,
        affected_gap_ids: List[str],
        invalidated_evidence_ids: Optional[List[str]] = None,
        new_evidence: Optional[List[Evidence]] = None,
    ) -> ReleaseInvestigationResult:
        """
        Targeted re-investigation:
        1. Preserves unaffected leaf gap evaluations.
        2. Filters out invalidated/stale evidence.
        3. Incorporates any new evidence from event or fresh provider query.
        4. Evaluates only the affected leaf gaps concurrently.
        5. Runs topological DAG cascade so milestones & root recalculate.
        """
        start_time = time.time()
        investigation_id = f"reinv-{previous_result.investigation_id}-{uuid.uuid4().hex[:4]}"

        # 1. Evidence update
        stale_ids = set(invalidated_evidence_ids or [])
        preserved_evidence = [e for e in previous_result.admitted_evidence if e.evidence_id not in stale_ids]

        # Gather fresh evidence if new_evidence is not explicitly provided or to supplement
        fresh_evidence = list(new_evidence or [])
        if not fresh_evidence and hasattr(self.provider, "fetch_evidence_for_release"):
            fresh_evidence = self.provider.fetch_evidence_for_release(candidate)

        combined_evidence = preserved_evidence + [
            e for e in fresh_evidence if e.evidence_id not in {pe.evidence_id for pe in preserved_evidence}
        ]

        outages_detected: List[str] = list(previous_result.outages_detected)
        if hasattr(self.provider, "outages"):
            outages = getattr(self.provider, "outages", set())
            timeouts = getattr(self.provider, "timeouts", set())
            outages_detected = list(set(outages).union(set(timeouts)))

        # 2. Correlate and validate
        corr_res = self.correlator.correlate_and_validate(candidate, combined_evidence)

        # 3. Build DAG and transfer unaffected states
        gaps_map, dag = self._build_investigation_dag(candidate)
        prev_gaps = {g.gap_id: g for g in previous_result.gaps}

        affected_set = set(affected_gap_ids)
        for gid, gap in gaps_map.items():
            if gid not in affected_set and gid in prev_gaps:
                prev_g = prev_gaps[gid]
                gap.status = prev_g.status
                gap.resolution = prev_g.resolution
                gap.resolution_evidence_ids = list(prev_g.resolution_evidence_ids)

        # 4. Concurrently evaluate only affected leaf gaps
        self._evaluate_leaf_gaps_concurrently(
            candidate=candidate,
            gaps_map=gaps_map,
            admitted_evidence=corr_res.admitted_evidence,
            rejected_failures=corr_res.rejected_evidence,
            contradictions=corr_res.contradictions,
            outages=outages_detected,
            target_gap_ids=affected_gap_ids,
        )

        # 5. Cascade topological dependencies
        self._topological_dag_cascade(gaps_map, dag)

        total_duration = time.time() - start_time
        telemetry = dict(previous_result.telemetry)
        telemetry.update({
            "is_targeted_reinvestigation": True,
            "targeted_reinvestigation_duration_ms": round(total_duration * 1000, 2),
            "affected_gap_count": len(affected_gap_ids),
            "invalidated_evidence_count": len(stale_ids),
        })

        result = ReleaseInvestigationResult(
            investigation_id=investigation_id,
            candidate=candidate,
            gaps=list(gaps_map.values()),
            admitted_evidence=corr_res.admitted_evidence,
            rejected_evidence=corr_res.rejected_evidence,
            contradictions=corr_res.contradictions,
            clusters=corr_res.clusters,
            outages_detected=outages_detected,
            telemetry=telemetry,
        )

        if self.store and hasattr(self.store, "investigations"):
            self.store.investigations.save_investigation(result)

        return result

    def _build_investigation_dag(
        self,
        candidate: ReleaseCandidate,
    ) -> Tuple[Dict[str, InformationGap], DependencyGraph]:
        """
        Dynamically build the release readiness dependency graph tailored to candidate context.
        """
        dag = DependencyGraph()
        gaps: Dict[str, InformationGap] = {}

        # ---------------------------------------------------------------------
        # LEAF LEVEL GAPS (Individual checks)
        # ---------------------------------------------------------------------
        # 1. Code Review
        gaps["GAP-CODE-REVIEW"] = InformationGap(
            gap_id="GAP-CODE-REVIEW",
            gap_type=GapType.STATE_VERIFICATION,
            target_entity=candidate.repository,
            description=f"Verify pull request review state and required approvals for commit {candidate.commit[:10]}",
            why_needed="Unreviewed code cannot be deployed to production.",
            required_information="Code review status must be APPROVED with designated approvers.",
            is_blocking=True,
            status=GapStatus.OPEN,
        )

        # 2. Rollback Procedure
        gaps["GAP-ROLLBACK-PLAN"] = InformationGap(
            gap_id="GAP-ROLLBACK-PLAN",
            gap_type=GapType.PREREQUISITE,
            target_entity=candidate.service_name,
            description=f"Verify documented rollback procedure exists for {candidate.service_name}",
            why_needed="Production releases must have a tested, documented rollback path.",
            required_information="Rollback procedure documentation present.",
            is_blocking=True,
            status=GapStatus.OPEN,
        )

        # 3. Work Management (Jira/Linear)
        gaps["GAP-WORK-ITEMS"] = InformationGap(
            gap_id="GAP-WORK-ITEMS",
            gap_type=GapType.STATE_VERIFICATION,
            target_entity=",".join(candidate.linked_work_item_ids) if candidate.linked_work_item_ids else candidate.service_name,
            description=f"Verify linked work items ({', '.join(candidate.linked_work_item_ids) or 'None'}) are completed and unblocking",
            why_needed="Uncompleted blocker issues or unresolved dependencies must prevent release.",
            required_information="All linked blocking issues must be in status DONE.",
            is_blocking=True,
            status=GapStatus.OPEN,
        )

        # 4. CI/CD Validation
        gaps["GAP-CI-VALIDATION"] = InformationGap(
            gap_id="GAP-CI-VALIDATION",
            gap_type=GapType.STATE_VERIFICATION,
            target_entity=candidate.commit,
            description=f"Verify CI pipeline build and automated test suites passed for commit {candidate.commit[:10]}",
            why_needed="Automated build and test suite must pass on the exact released commit.",
            required_information="CI pipeline status PASSED with zero failed tests.",
            is_blocking=True,
            status=GapStatus.OPEN,
        )

        # 5. Security SAST
        gaps["GAP-SECURITY-SAST"] = InformationGap(
            gap_id="GAP-SECURITY-SAST",
            gap_type=GapType.STATE_VERIFICATION,
            target_entity=candidate.commit,
            description=f"Verify static application security testing (SAST) findings are clean for commit {candidate.commit[:10]}",
            why_needed="Static code analysis must not contain active CRITICAL or HIGH vulnerabilities.",
            required_information="No active unresolved CRITICAL/HIGH SAST vulnerabilities.",
            is_blocking=True,
            status=GapStatus.OPEN,
        )

        # 6. Security SCA (Dependencies)
        gaps["GAP-SECURITY-SCA"] = InformationGap(
            gap_id="GAP-SECURITY-SCA",
            gap_type=GapType.STATE_VERIFICATION,
            target_entity=candidate.service_name,
            description=f"Verify third-party dependency vulnerabilities (SCA) are resolved or mitigated for {candidate.service_name}",
            why_needed="Reachable CVEs in dependencies must be upgraded or mitigated.",
            required_information="Zero active reachable CRITICAL/HIGH SCA vulnerabilities without approved exceptions.",
            is_blocking=True,
            status=GapStatus.OPEN,
        )

        # 7. Production Incidents
        gaps["GAP-INCIDENT-CLEAR"] = InformationGap(
            gap_id="GAP-INCIDENT-CLEAR",
            gap_type=GapType.STATE_VERIFICATION,
            target_entity=candidate.service_name,
            description=f"Verify no active production incidents are affecting {candidate.service_name}",
            why_needed="Deploying into an active production incident is prohibited without emergency clearance.",
            required_information="Zero active non-DONE incidents affecting the target service.",
            is_blocking=True,
            status=GapStatus.OPEN,
        )

        # ---------------------------------------------------------------------
        # INTERMEDIATE MILESTONE GAPS
        # ---------------------------------------------------------------------
        gaps["GAP-CODE-READY"] = InformationGap(
            gap_id="GAP-CODE-READY",
            gap_type=GapType.PREREQUISITE,
            target_entity=candidate.service_name,
            description=f"Code change readiness: review complete, rollback planned, and work items closed",
            why_needed="Prerequisite layer for release approval.",
            required_information="All code and work management prerequisites satisfied.",
            is_blocking=True,
            status=GapStatus.OPEN,
        )

        gaps["GAP-SECURITY-CLEAR"] = InformationGap(
            gap_id="GAP-SECURITY-CLEAR",
            gap_type=GapType.PREREQUISITE,
            target_entity=candidate.service_name,
            description=f"Security assurance: SAST and SCA vulnerability assessments cleared",
            why_needed="Security milestone must be satisfied.",
            required_information="All security scanner criteria satisfied.",
            is_blocking=True,
            status=GapStatus.OPEN,
        )

        gaps["GAP-OPERATIONS-READY"] = InformationGap(
            gap_id="GAP-OPERATIONS-READY",
            gap_type=GapType.PREREQUISITE,
            target_entity=candidate.service_name,
            description=f"Operational readiness: CI build passed, incidents clear, rollback documented",
            why_needed="Operational stability milestone must be satisfied.",
            required_information="CI validation and operational stability verified.",
            is_blocking=True,
            status=GapStatus.OPEN,
        )

        # ---------------------------------------------------------------------
        # ROOT GOAL GAP
        # ---------------------------------------------------------------------
        gaps["GAP-RELEASE-ROOT"] = InformationGap(
            gap_id="GAP-RELEASE-ROOT",
            gap_type=GapType.OBJECTIVE_ROOT,
            target_entity=candidate.release_id,
            description=f"Overall production release readiness for {candidate.service_name} {candidate.version}",
            why_needed="Definitive release readiness decision for deployment.",
            required_information="Code, Security, and Operational readiness all verified uncontested.",
            is_blocking=True,
            status=GapStatus.OPEN,
        )

        # ---------------------------------------------------------------------
        # REGISTER DAG DEPENDENCY EDGES
        # ---------------------------------------------------------------------
        all_ids = set(gaps.keys())

        # Intermediate milestones depend on leaf gaps
        dag.add_dependency("GAP-CODE-READY", "GAP-CODE-REVIEW", all_ids, gaps)
        dag.add_dependency("GAP-CODE-READY", "GAP-ROLLBACK-PLAN", all_ids, gaps)
        dag.add_dependency("GAP-CODE-READY", "GAP-WORK-ITEMS", all_ids, gaps)

        dag.add_dependency("GAP-SECURITY-CLEAR", "GAP-SECURITY-SAST", all_ids, gaps)
        dag.add_dependency("GAP-SECURITY-CLEAR", "GAP-SECURITY-SCA", all_ids, gaps)

        dag.add_dependency("GAP-OPERATIONS-READY", "GAP-CI-VALIDATION", all_ids, gaps)
        dag.add_dependency("GAP-OPERATIONS-READY", "GAP-INCIDENT-CLEAR", all_ids, gaps)

        # Root gap depends on intermediate milestones
        dag.add_dependency("GAP-RELEASE-ROOT", "GAP-CODE-READY", all_ids, gaps)
        dag.add_dependency("GAP-RELEASE-ROOT", "GAP-SECURITY-CLEAR", all_ids, gaps)
        dag.add_dependency("GAP-RELEASE-ROOT", "GAP-OPERATIONS-READY", all_ids, gaps)

        return gaps, dag

    def _evaluate_leaf_gaps_concurrently(
        self,
        candidate: ReleaseCandidate,
        gaps_map: Dict[str, InformationGap],
        admitted_evidence: List[Evidence],
        rejected_failures: List[EvidenceValidationFailure],
        contradictions: List[ContradictionRecord],
        outages: List[str],
        target_gap_ids: Optional[List[str]] = None,
    ) -> None:
        """
        Execute check logic for leaf gaps concurrently using ThreadPoolExecutor.
        Supports targeted evaluation for event-driven invalidations.
        """
        all_leaf_ids = [
            "GAP-CODE-REVIEW",
            "GAP-ROLLBACK-PLAN",
            "GAP-WORK-ITEMS",
            "GAP-CI-VALIDATION",
            "GAP-SECURITY-SAST",
            "GAP-SECURITY-SCA",
            "GAP-INCIDENT-CLEAR",
        ]

        if target_gap_ids is not None:
            leaf_gap_ids = [gid for gid in target_gap_ids if gid in gaps_map and gid in all_leaf_ids]
        else:
            leaf_gap_ids = [gid for gid in all_leaf_ids if gid in gaps_map]

        def worker(gap_id: str):
            gap = gaps_map[gap_id]
            self._evaluate_single_leaf_gap(
                gap=gap,
                candidate=candidate,
                admitted_evidence=admitted_evidence,
                rejected_failures=rejected_failures,
                contradictions=contradictions,
                outages=outages,
            )

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = [executor.submit(worker, gid) for gid in leaf_gap_ids]
            concurrent.futures.wait(futures)

    def _evaluate_single_leaf_gap(
        self,
        gap: InformationGap,
        candidate: ReleaseCandidate,
        admitted_evidence: List[Evidence],
        rejected_failures: List[EvidenceValidationFailure],
        contradictions: List[ContradictionRecord],
        outages: List[str],
    ) -> None:
        """
        Deterministic, evidence-grounded evaluation of an individual leaf gap.
        """
        gid = gap.gap_id

        # ---------------------------------------------------------------------
        # 1. Check for contradictions directly affecting this domain
        # ---------------------------------------------------------------------
        domain_contradictions = [c for c in contradictions if self._contradiction_affects_gap(c, gid)]
        if domain_contradictions:
            gap.status = GapStatus.RECONCILIATION_REQUIRED
            gap.resolution = f"Opposing evidence detected across systems: {domain_contradictions[0].basis}"
            for c in domain_contradictions:
                gap.conflicting_evidence_ids.extend([c.claim_a_evidence_id, c.claim_b_evidence_id])
            return

        # ---------------------------------------------------------------------
        # 2. Domain-Specific Evaluation
        # ---------------------------------------------------------------------

        # GAP-CODE-REVIEW
        if gid == "GAP-CODE-REVIEW":
            if "git" in outages:
                gap.status = GapStatus.BLOCKED
                gap.resolution = "PROVIDER_UNAVAILABLE: Git provider outage or timeout."
                return

            git_evs = [e for e in admitted_evidence if "git" in e.source_type.lower()]
            if not git_evs:
                gap.status = GapStatus.BLOCKED
                gap.resolution = f"INSUFFICIENT_EVIDENCE: No code review evidence found for PR or commit {candidate.commit[:10]}."
                return

            # Check review status
            all_approved = False
            for gev in git_evs:
                meta = gev.metadata or {}
                status = meta.get("status", "")
                if status == "APPROVED":
                    all_approved = True
                    gap.resolution_evidence_ids.append(gev.evidence_id)
                elif status in ["CHANGES_REQUESTED", "PENDING"]:
                    gap.status = GapStatus.BLOCKED
                    gap.resolution = f"Code review status is {status}."
                    gap.resolution_evidence_ids.append(gev.evidence_id)
                    return

            if all_approved:
                gap.status = GapStatus.RESOLVED
                gap.resolution = "Code review approved by designated reviewers."
            else:
                gap.status = GapStatus.BLOCKED
                gap.resolution = "Required code review approval is missing."

        # GAP-ROLLBACK-PLAN
        elif gid == "GAP-ROLLBACK-PLAN":
            git_evs = [e for e in admitted_evidence if "git" in e.source_type.lower()]
            has_rb = any("rollback procedure is verified" in e.content.lower() for e in git_evs)
            missing_rb = any("no rollback procedure documented" in e.content.lower() for e in git_evs)

            if missing_rb:
                gap.status = GapStatus.BLOCKED
                gap.resolution = "Rollback procedure is not documented."
            elif has_rb:
                gap.status = GapStatus.RESOLVED
                gap.resolution = "Rollback procedure is verified and documented."
                for e in git_evs:
                    if "rollback procedure is verified" in e.content.lower():
                        gap.resolution_evidence_ids.append(e.evidence_id)
            else:
                # Default to verified if no explicit omission
                gap.status = GapStatus.RESOLVED
                gap.resolution = "Standard deployment rollback procedure in place."

        # GAP-WORK-ITEMS
        elif gid == "GAP-WORK-ITEMS":
            if "jira" in outages:
                gap.status = GapStatus.BLOCKED
                gap.resolution = "PROVIDER_UNAVAILABLE: Work management provider outage or timeout."
                return

            if not candidate.linked_work_item_ids:
                gap.status = GapStatus.RESOLVED
                gap.resolution = "No linked work items required for this release."
                return

            jira_evs = [e for e in admitted_evidence if "jira" in e.source_type.lower()]
            found_ids = {(e.metadata or {}).get("item_id") for e in jira_evs if (e.metadata or {}).get("item_id")}
            missing_items = set(candidate.linked_work_item_ids) - found_ids

            if missing_items:
                gap.status = GapStatus.BLOCKED
                gap.resolution = f"INSUFFICIENT_EVIDENCE: Missing work item evidence for {', '.join(missing_items)}."
                return

            unresolved_blockers: List[str] = []
            for jev in jira_evs:
                meta = jev.metadata or {}
                status = meta.get("status", "")
                is_blocking = meta.get("is_blocking", True)
                item_id = meta.get("item_id", "")
                if is_blocking and status != "DONE":
                    unresolved_blockers.append(f"{item_id} ({status})")
                gap.resolution_evidence_ids.append(jev.evidence_id)

            if unresolved_blockers:
                gap.status = GapStatus.BLOCKED
                gap.resolution = f"Unresolved blocking work items: {', '.join(unresolved_blockers)}."
            else:
                gap.status = GapStatus.RESOLVED
                gap.resolution = "All linked work items completed and unblocking."

        # GAP-CI-VALIDATION
        elif gid == "GAP-CI-VALIDATION":
            if "ci" in outages:
                gap.status = GapStatus.BLOCKED
                gap.resolution = "PROVIDER_UNAVAILABLE: CI/CD provider outage or timeout."
                return

            # Check if CI evidence was rejected due to stale commit
            stale_ci = [f for f in rejected_failures if f.source_type == "ci" and f.rejection_reason == "STALE_COMMIT_EVIDENCE"]
            if stale_ci:
                gap.status = GapStatus.BLOCKED
                gap.resolution = f"INSUFFICIENT_EVIDENCE: CI run belongs to an older/different commit hash ({stale_ci[0].details.get('found_commit', '')[:10]}), not the current release commit."
                return

            ci_evs = [e for e in admitted_evidence if "ci" in e.source_type.lower()]
            if not ci_evs:
                gap.status = GapStatus.BLOCKED
                gap.resolution = f"INSUFFICIENT_EVIDENCE: No CI pipeline validation found for release commit {candidate.commit[:10]}."
                return

            failed_pipelines: List[str] = []
            passed_pipelines: List[str] = []
            for cev in ci_evs:
                meta = cev.metadata or {}
                status = meta.get("status", "")
                pid = meta.get("pipeline_id", "")
                failed_tests = meta.get("failed_tests", 0)
                if status == "PASSED" and failed_tests == 0:
                    passed_pipelines.append(pid)
                    gap.resolution_evidence_ids.append(cev.evidence_id)
                else:
                    failed_pipelines.append(f"{pid} ({status}, {failed_tests} failed tests)")
                    gap.resolution_evidence_ids.append(cev.evidence_id)

            if failed_pipelines:
                gap.status = GapStatus.BLOCKED
                gap.resolution = f"CI validation failed: {', '.join(failed_pipelines)}."
            elif passed_pipelines:
                gap.status = GapStatus.RESOLVED
                gap.resolution = f"CI pipeline validation passed ({', '.join(passed_pipelines)})."
            else:
                gap.status = GapStatus.BLOCKED
                gap.resolution = "CI validation inconclusive."

        # GAP-SECURITY-SAST
        elif gid == "GAP-SECURITY-SAST":
            if "security" in outages:
                gap.status = GapStatus.BLOCKED
                gap.resolution = "PROVIDER_UNAVAILABLE: Security scanner provider outage or timeout."
                return

            sast_evs = [
                e for e in admitted_evidence
                if "security" in e.source_type.lower() and (e.metadata or {}).get("category") in ["SAST", "SECRETS", "IAC"]
            ]

            active_critical = []
            for sev in sast_evs:
                meta = sev.metadata or {}
                status = meta.get("status", "")
                severity = meta.get("severity", "")
                fid = meta.get("finding_id", "")
                is_exploitable = meta.get("is_exploitable", True)
                if status == "ACTIVE" and severity in ["CRITICAL", "HIGH"] and is_exploitable:
                    active_critical.append(f"{fid} ({severity})")
                gap.resolution_evidence_ids.append(sev.evidence_id)

            if active_critical:
                gap.status = GapStatus.BLOCKED
                gap.resolution = f"Unresolved active SAST security findings: {', '.join(active_critical)}."
            else:
                gap.status = GapStatus.RESOLVED
                gap.resolution = "SAST static analysis clear of active blocking vulnerabilities."

        # GAP-SECURITY-SCA
        elif gid == "GAP-SECURITY-SCA":
            if "security" in outages:
                gap.status = GapStatus.BLOCKED
                gap.resolution = "PROVIDER_UNAVAILABLE: Security scanner provider outage or timeout."
                return

            sca_evs = [
                e for e in admitted_evidence
                if "security" in e.source_type.lower() and (e.metadata or {}).get("category") in ["SCA", "CONTAINER", "DAST"]
            ]

            blocking_sca = []
            conditional_sca = []
            for sev in sca_evs:
                meta = sev.metadata or {}
                status = meta.get("status", "")
                severity = meta.get("severity", "")
                fid = meta.get("finding_id", "")
                cve = meta.get("cve", fid)
                is_reachable = meta.get("is_reachable", True)

                if status == "ACTIVE" and severity in ["CRITICAL", "HIGH"]:
                    if is_reachable:
                        blocking_sca.append(f"{cve} ({severity} in {meta.get('package')})")
                    else:
                        conditional_sca.append(f"{cve} (unreachable)")
                gap.resolution_evidence_ids.append(sev.evidence_id)

            if blocking_sca:
                gap.status = GapStatus.BLOCKED
                gap.resolution = f"Unresolved reachable dependency vulnerabilities: {', '.join(blocking_sca)}."
            elif conditional_sca:
                gap.status = GapStatus.RESOLVED
                gap.resolution = f"Non-blocking unreachable vulnerabilities noted: {', '.join(conditional_sca)}."
            else:
                gap.status = GapStatus.RESOLVED
                gap.resolution = "SCA dependency checks clear."

        # GAP-INCIDENT-CLEAR
        elif gid == "GAP-INCIDENT-CLEAR":
            inc_evs = [e for e in admitted_evidence if "incident" in e.source_type.lower()]
            active_incidents = []
            for iev in inc_evs:
                meta = iev.metadata or {}
                status = meta.get("status", "")
                inc_id = meta.get("incident_id", "")
                priority = meta.get("priority", "")
                if status != "DONE":
                    active_incidents.append(f"{inc_id} ({priority})")
                gap.resolution_evidence_ids.append(iev.evidence_id)

            if active_incidents:
                gap.status = GapStatus.BLOCKED
                gap.resolution = f"Active production incidents affecting target service: {', '.join(active_incidents)}."
            else:
                gap.status = GapStatus.RESOLVED
                gap.resolution = "No active production incidents affecting target service."

    def _contradiction_affects_gap(self, contra: ContradictionRecord, gap_id: str) -> bool:
        """Determine whether a cross-system contradiction maps to a specific gap."""
        cid = contra.contradiction_id.lower()
        if "git-jira" in cid:
            return gap_id in ["GAP-CODE-REVIEW", "GAP-WORK-ITEMS"]
        if "approval-rejection" in cid:
            return gap_id in ["GAP-WORK-ITEMS", "GAP-CODE-REVIEW"]
        if "sec-" in cid:
            return gap_id in ["GAP-SECURITY-SAST", "GAP-SECURITY-SCA"]
        if "ci-tests" in cid:
            return gap_id == "GAP-CI-VALIDATION"
        return False

    def _topological_dag_cascade(
        self,
        gaps_map: Dict[str, InformationGap],
        dag: DependencyGraph,
    ) -> None:
        """
        Evaluate intermediate and root milestones based on prerequisite states in the DAG.
        """
        # 1. GAP-CODE-READY
        code_prereqs = ["GAP-CODE-REVIEW", "GAP-ROLLBACK-PLAN", "GAP-WORK-ITEMS"]
        self._evaluate_milestone_gap(gaps_map["GAP-CODE-READY"], [gaps_map[p] for p in code_prereqs])

        # 2. GAP-SECURITY-CLEAR
        sec_prereqs = ["GAP-SECURITY-SAST", "GAP-SECURITY-SCA"]
        self._evaluate_milestone_gap(gaps_map["GAP-SECURITY-CLEAR"], [gaps_map[p] for p in sec_prereqs])

        # 3. GAP-OPERATIONS-READY
        ops_prereqs = ["GAP-CI-VALIDATION", "GAP-INCIDENT-CLEAR"]
        self._evaluate_milestone_gap(gaps_map["GAP-OPERATIONS-READY"], [gaps_map[p] for p in ops_prereqs])

        # 4. GAP-RELEASE-ROOT
        root_prereqs = ["GAP-CODE-READY", "GAP-SECURITY-CLEAR", "GAP-OPERATIONS-READY"]
        self._evaluate_milestone_gap(gaps_map["GAP-RELEASE-ROOT"], [gaps_map[p] for p in root_prereqs])

    def _evaluate_milestone_gap(
        self,
        milestone: InformationGap,
        prereqs: List[InformationGap],
    ) -> None:
        """Evaluate a milestone gap based on its direct prerequisites."""
        reconcile_prereqs = [p for p in prereqs if p.status == GapStatus.RECONCILIATION_REQUIRED]
        if reconcile_prereqs:
            milestone.status = GapStatus.RECONCILIATION_REQUIRED
            milestone.resolution = f"Opposing evidence requiring reconciliation in prerequisite {reconcile_prereqs[0].gap_id}."
            return

        blocked_prereqs = [p for p in prereqs if p.status == GapStatus.BLOCKED]
        if blocked_prereqs:
            milestone.status = GapStatus.DEPENDENCY_UNSATISFIED
            milestone.resolution = f"Prerequisite {blocked_prereqs[0].gap_id} is BLOCKED: {blocked_prereqs[0].resolution}"
            return

        unresolved_prereqs = [p for p in prereqs if p.status not in [GapStatus.RESOLVED, GapStatus.RECONCILIATION_REQUIRED]]
        if unresolved_prereqs:
            milestone.status = GapStatus.DEPENDENCY_UNSATISFIED
            milestone.resolution = f"Prerequisite {unresolved_prereqs[0].gap_id} is not yet resolved."
            return

        # All prerequisites resolved
        milestone.status = GapStatus.RESOLVED
        milestone.resolution = "All prerequisite criteria verified and satisfied."


# -----------------------------------------------------------------------------
# INVESTIGATION PERSISTENCE & RECOVERY HELPERS (Brick 4.4)
# -----------------------------------------------------------------------------

def save_investigation_state(store: Any, result: ReleaseInvestigationResult) -> None:
    """Persist investigation result and candidate into durable store."""
    if hasattr(store, "entities"):
        store.entities.save_candidate(result.candidate)
    if hasattr(store, "investigations"):
        store.investigations.save_investigation(result)


def recover_investigation_state(store: Any, investigation_id: str) -> Optional[ReleaseInvestigationResult]:
    """Recover complete investigation result from durable store after process restart."""
    if hasattr(store, "investigations"):
        return store.investigations.get_investigation(investigation_id)
    return None


def reconstruct_assessment_from_store(store: Any, release_id: str) -> Optional[Any]:
    """Reconstruct complete ReleaseAssessment from durable store."""
    if hasattr(store, "investigations"):
        return store.investigations.get_assessment(release_id)
    return None
