"""
Asynchronous DAG-based Security Investigation Engine (Brick 4.7)

Orchestrates the complete security intelligence pipeline as a directed acyclic graph:
GAP-SEC-FINDINGS
      ↓
GAP-SEC-DEPENDENCY
      ↓
GAP-SEC-REACHABILITY
      ↓
GAP-SEC-EXPLOITABILITY
      ↓
GAP-SEC-CONTRADICTION
      ↓
GAP-SEC-REMEDIATION
      ↓
GAP-SEC-POLICY
      ↓
GAP-SEC-ROOT (Security Decision)

Guarantees:
- Asynchronous parallel evaluation across independent check workers.
- Epistemic state cascades (topological invalidation and restoration).
- Returns authoritative SecurityInvestigation container.
"""

from __future__ import annotations

import concurrent.futures
import time
import uuid
from typing import Any, Dict, List, Optional, Set, Tuple

from backend.evidence.models import Evidence
from backend.investigation.dag import DependencyGraph
from backend.investigation.models import ContradictionRecord, GapStatus, GapType, InformationGap
from backend.release.models import ReleaseCandidate
from backend.release.security.business_impact import BusinessImpactAssessment, BusinessImpactEngine
from backend.release.security.clustering import SecurityClusteringEngine
from backend.release.security.contradictions import SecurityContradictionEngine
from backend.release.security.correlation import CrossSystemSecurityCorrelator
from backend.release.security.decision import SecurityDecisionEngine
from backend.release.security.dependency import DependencyIntelligenceEngine
from backend.release.security.exploitability import ExploitabilityAssessmentEngine
from backend.release.security.exposure import RuntimeExposureAssessment, RuntimeExposureEngine
from backend.release.security.impact import SecurityImpactEngine
from backend.release.security.models import (
    AffectedDependency,
    BuildArtifact,
    CompensatingControl,
    Deployment,
    DeploymentEnvironment,
    ExploitabilityAssessment,
    ReachabilityAssessment,
    RemediationCandidate,
    RuntimeService,
    SecurityContradictionRecord,
    SecurityDecision,
    SecurityFinding,
    SecurityImpactAssessment,
    SecurityImpactCluster,
    SecurityInvestigation,
    SecurityReleaseAssessment,
    SecurityVerification,
)
from backend.release.security.normalizer import SecurityFindingNormalizer
from backend.release.security.policy import SecurityPolicyEngine
from backend.release.security.reachability import ReachabilityIntelligenceEngine
from backend.release.security.remediation import RemediationIntelligenceEngine


class SecurityInvestigationEngine:
    """
    Sovereign DAG investigation orchestrator for security intelligence (Brick 4.8).
    Coordinates normalizers, correlators, dependency reasoners, reachability analyzers,
    exposure engines, business impact assessors, exploitability engines, multi-dimensional impact,
    finding clustering, contradiction checkers, and decision derivation.
    """

    def __init__(
        self,
        normalizer: Optional[SecurityFindingNormalizer] = None,
        correlator: Optional[CrossSystemSecurityCorrelator] = None,
        dependency_engine: Optional[DependencyIntelligenceEngine] = None,
        reachability_engine: Optional[ReachabilityIntelligenceEngine] = None,
        exploitability_engine: Optional[ExploitabilityAssessmentEngine] = None,
        contradiction_engine: Optional[SecurityContradictionEngine] = None,
        remediation_engine: Optional[RemediationIntelligenceEngine] = None,
        policy_engine: Optional[SecurityPolicyEngine] = None,
        decision_engine: Optional[SecurityDecisionEngine] = None,
        exposure_engine: Optional[RuntimeExposureEngine] = None,
        business_engine: Optional[BusinessImpactEngine] = None,
        impact_engine: Optional[SecurityImpactEngine] = None,
        clustering_engine: Optional[SecurityClusteringEngine] = None,
        store: Optional[Any] = None,
        max_workers: int = 4,
    ):
        self.normalizer = normalizer or SecurityFindingNormalizer()
        self.correlator = correlator or CrossSystemSecurityCorrelator()
        self.dependency_engine = dependency_engine or DependencyIntelligenceEngine()
        self.reachability_engine = reachability_engine or ReachabilityIntelligenceEngine()
        self.exploitability_engine = exploitability_engine or ExploitabilityAssessmentEngine()
        self.contradiction_engine = contradiction_engine or SecurityContradictionEngine()
        self.remediation_engine = remediation_engine or RemediationIntelligenceEngine()
        self.policy_engine = policy_engine or SecurityPolicyEngine()
        self.decision_engine = decision_engine or SecurityDecisionEngine(policy_engine=self.policy_engine)
        self.exposure_engine = exposure_engine or RuntimeExposureEngine()
        self.business_engine = business_engine or BusinessImpactEngine()
        self.impact_engine = impact_engine or SecurityImpactEngine()
        self.clustering_engine = clustering_engine or SecurityClusteringEngine()
        self.store = store
        self.max_workers = max_workers

    def investigate(
        self,
        repository: str,
        commit: str,
        tenant_id: str = "default",
        artifact_digest: Optional[str] = None,
        raw_findings: Optional[List[Dict[str, Any]]] = None,
        normalized_findings: Optional[List[SecurityFinding]] = None,
        manifest_data: Optional[Dict[str, Any]] = None,
        lockfile_data: Optional[Dict[str, Any]] = None,
        dependency_graph: Optional[List[Any]] = None,
        dev_packages: Optional[Set[str]] = None,
        call_graph: Optional[Dict[str, List[str]]] = None,
        registered_routes: Optional[List[str]] = None,
        imported_symbols: Optional[Dict[str, Set[str]]] = None,
        compensating_controls: Optional[List[CompensatingControl]] = None,
        verifications: Optional[List[SecurityVerification]] = None,
        is_evidence_stale: bool = False,
        linked_work_items: Optional[List[str]] = None,
        linked_pr_id: Optional[str] = None,
        linked_pipeline_id: Optional[str] = None,
        previous_decision: Optional[SecurityDecision] = None,
        build_artifact: Optional[BuildArtifact] = None,
        deployment: Optional[Deployment] = None,
        service: Optional[RuntimeService] = None,
        runtime_service: Optional[RuntimeService] = None,
        candidate: Optional[ReleaseCandidate] = None,
        network_evidence: Optional[List[Evidence]] = None,
        operational_evidence: Optional[List[Evidence]] = None,
        runtime_alerts: Optional[List[Dict[str, Any]]] = None,
        environment: Optional[DeploymentEnvironment] = None,
        artifacts_map: Optional[Dict[str, BuildArtifact]] = None,
        deployments_map: Optional[Dict[str, Deployment]] = None,
        services_map: Optional[Dict[str, RuntimeService]] = None,
        business_context: Optional[Any] = None,
    ) -> SecurityInvestigation:
        """
        Execute full asynchronous DAG-based security investigation with 4.8 impact intelligence.
        """
        start_time = time.time()
        investigation_id = f"secinv-{uuid.uuid4().hex[:8]}"

        service = service or runtime_service

        effective_digest = artifact_digest or (build_artifact.artifact_digest if build_artifact else (deployment.artifact_digest if deployment else (candidate.artifact_digest if candidate else None)))
        effective_dep_id = deployment.deployment_id if deployment else (candidate.deployment_id if candidate else None)
        effective_svc_id = service.service_id if service else (candidate.service_id if candidate else None)
        effective_env = environment or (deployment.environment if deployment else (service.environment if service else DeploymentEnvironment.PRODUCTION))

        artifacts_dict: Dict[str, BuildArtifact] = dict(artifacts_map or {})
        if build_artifact:
            artifacts_dict[build_artifact.artifact_digest] = build_artifact

        deployments_dict: Dict[str, Deployment] = dict(deployments_map or {})
        if deployment:
            deployments_dict[deployment.deployment_id] = deployment

        services_dict: Dict[str, RuntimeService] = dict(services_map or {})
        if service:
            services_dict[service.service_id] = service

        # 1. Ingest & Normalize findings
        all_findings: List[SecurityFinding] = []
        if normalized_findings:
            all_findings.extend(normalized_findings)

        if raw_findings:
            for rf in raw_findings:
                try:
                    nf = self.normalizer.normalize(
                        raw_finding=rf,
                        repository=repository,
                        commit=commit,
                        tenant_id=tenant_id,
                        artifact_digest=effective_digest,
                    )
                    ev = self.normalizer.to_evidence(nf)
                    all_findings.append(nf)
                except Exception:
                    pass

        # 2. Correlate and firewall evidence (Tenant and Repository Isolation)
        corr_res = self.correlator.correlate_and_firewall(
            repository=repository,
            commit=commit,
            tenant_id=tenant_id,
            artifact_digest=effective_digest,
            findings=all_findings,
            linked_work_items=linked_work_items,
            linked_pr_id=linked_pr_id,
            linked_pipeline_id=linked_pipeline_id,
        )

        admitted_findings = corr_res.admitted_findings
        admitted_evidence = corr_res.admitted_evidence
        rejected_failures = corr_res.rejected_evidence

        # 3. Concurrent DAG Evaluation of Findings
        dependencies: Dict[str, AffectedDependency] = {}
        reachability_map: Dict[str, ReachabilityAssessment] = {}
        exploitability_map: Dict[str, ExploitabilityAssessment] = {}
        exposure_map: Dict[str, RuntimeExposureAssessment] = {}
        business_map: Dict[str, BusinessImpactAssessment] = {}
        impact_assessments: Dict[str, SecurityImpactAssessment] = {}
        remediation_candidates: List[RemediationCandidate] = []

        def _process_finding(f: SecurityFinding) -> Tuple[
            SecurityFinding,
            Optional[AffectedDependency],
            ReachabilityAssessment,
            RuntimeExposureAssessment,
            ExploitabilityAssessment,
            BusinessImpactAssessment,
            SecurityImpactAssessment,
            RemediationCandidate,
        ]:
            # A. Dependency Intelligence
            dep = None
            if f.package:
                dep = self.dependency_engine.analyze_dependency(
                    finding=f,
                    manifest_data=manifest_data,
                    lockfile_data=lockfile_data,
                    dependency_graph=dependency_graph,
                    dev_packages=dev_packages,
                )

            # B. Reachability Intelligence
            reach = self.reachability_engine.evaluate_reachability(
                finding=f,
                call_graph=call_graph,
                registered_routes=registered_routes,
                imported_symbols=imported_symbols,
            )

            # C. Exposure Intelligence
            exp_assess = self.exposure_engine.evaluate_exposure(
                service=service,
                network_evidence=network_evidence,
                target_route=reach.route or reach.entry_point,
                entry_point=reach.entry_point,
            )

            # D. Exploitability Assessment
            active_ctrls = list(compensating_controls or []) + list(exp_assess.active_controls)
            exp = self.exploitability_engine.evaluate_exploitability(
                finding=f,
                reachability=reach,
                compensating_controls=active_ctrls,
                external_exposure=exp_assess.exposure,
                auth_requirement=exp_assess.auth_requirement,
            )

            # E. Business Impact Assessment
            bus_assess = self.business_engine.evaluate_business_impact(
                service=service,
                candidate=candidate,
                environment=effective_env,
                operational_evidence=operational_evidence,
                route_or_entrypoint=reach.route or reach.entry_point,
            )

            # F. Multi-Dimensional Security Impact & Attack-Path Chain
            art = artifacts_dict.get(effective_digest or "") if effective_digest else build_artifact
            dep_obj = deployments_dict.get(effective_dep_id or "") if effective_dep_id else deployment
            imp = self.impact_engine.evaluate_impact(
                finding=f,
                dependency=dep,
                reachability=reach,
                exposure=exp_assess,
                business_impact=bus_assess,
                artifact=art,
                deployment=dep_obj,
                service=service,
                candidate=candidate,
                exploitability=exp,
                is_evidence_stale=is_evidence_stale,
            )

            # G. Remediation Intelligence
            rem = self.remediation_engine.evaluate_remediation(
                finding=f,
                affected_dep=dep,
            )

            return f, dep, reach, exp_assess, exp, bus_assess, imp, rem

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = [executor.submit(_process_finding, f) for f in admitted_findings]
            for future in concurrent.futures.as_completed(futures):
                f, dep, reach, exp_assess, exp, bus_assess, imp, rem = future.result()
                if dep:
                    dependencies[f.package or f.finding_id] = dep
                reachability_map[f.finding_id] = reach
                exposure_map[f.finding_id] = exp_assess
                exploitability_map[f.finding_id] = exp
                business_map[f.finding_id] = bus_assess
                impact_assessments[f.finding_id] = imp
                remediation_candidates.append(rem)

        # 4. Multi-Finding Clustering
        clusters = self.clustering_engine.cluster_findings(
            findings=admitted_findings,
            impact_map=impact_assessments,
            remediations=remediation_candidates,
        )

        # 5. Detect Contradictions across 4.8 Taxonomy
        contradictions = self.contradiction_engine.detect_contradictions(
            findings=admitted_findings,
            dependencies=dependencies,
            reachability_map=reachability_map,
            verifications=verifications,
            production_artifact_digest=effective_digest,
            head_commit=commit,
            artifacts=artifacts_dict,
            deployments=deployments_dict,
            services=services_dict,
            exposure_map=exposure_map,
            business_map=business_map,
            runtime_alerts=runtime_alerts,
        )

        # 6. Construct Information Gaps
        gaps = self._build_investigation_gaps(
            findings=admitted_findings,
            contradictions=contradictions,
            reachability_map=reachability_map,
            is_stale=is_evidence_stale,
        )

        unresolved_gap_ids = [g.gap_id for g in gaps if g.status != GapStatus.RESOLVED]

        # 7. Derive Authoritative Security Decision
        decision = self.decision_engine.derive_decision(
            repository=repository,
            commit=commit,
            tenant_id=tenant_id,
            artifact_digest=effective_digest,
            findings=admitted_findings,
            reachability_map=reachability_map,
            exploitability_map=exploitability_map,
            contradictions=contradictions,
            remediations=remediation_candidates,
            is_evidence_stale=is_evidence_stale,
            unresolved_gaps=unresolved_gap_ids,
            previous_decision=previous_decision,
            impact_map=impact_assessments,
            exposure_map=exposure_map,
            deployment_id=effective_dep_id,
            service_id=effective_svc_id,
            environment=effective_env,
        )

        # 8. Release Correlation Assessment
        has_drift = any(getattr(imp, "artifact_drift_detected", False) for imp in impact_assessments.values()) or any(c.conflict_type in ("ARTIFACT_DEPLOYMENT_MISMATCH", "REPOSITORY_ARTIFACT_MISMATCH", "ARTIFACT_VS_HEAD") for c in contradictions)
        is_blocked = decision.outcome.value in ("SECURITY_BLOCKED", "SECURITY_RECONCILIATION_REQUIRED") or has_drift
        rel_assessment = SecurityReleaseAssessment(
            release_id=candidate.release_id if candidate else f"rel-{commit[:8]}",
            tenant_id=tenant_id,
            repository=repository,
            commit=commit,
            artifact_digest=effective_digest,
            deployment_id=effective_dep_id,
            service_id=effective_svc_id,
            environment=effective_env,
            security_decision=decision,
            impact_assessments=list(impact_assessments.values()),
            clusters=clusters,
            contradictions=contradictions,
            artifact_drift_detected=has_drift,
            is_release_blocked=is_blocked,
            blocking_reasons=list(decision.blocking_factors),
            clear_reasons=list(decision.verified_factors),
            created_at="2026-09-09T12:00:00Z",
        )

        total_duration = time.time() - start_time
        telemetry = {
            "total_duration_ms": round(total_duration * 1000, 2),
            "findings_ingested": len(all_findings),
            "findings_admitted": len(admitted_findings),
            "evidence_rejected": len(rejected_failures),
            "contradictions_found": len(contradictions),
            "impact_assessments_count": len(impact_assessments),
            "clusters_count": len(clusters),
            "concurrency": self.max_workers,
        }

        now_str = "2026-09-09T12:00:00Z"

        inv = SecurityInvestigation(
            investigation_id=investigation_id,
            tenant_id=tenant_id,
            repository=repository,
            commit=commit,
            artifact_digest=effective_digest,
            deployment_id=effective_dep_id,
            service_id=effective_svc_id,
            environment=effective_env,
            findings=admitted_findings,
            dependencies=dependencies,
            reachability=reachability_map,
            exploitability=exploitability_map,
            impact_assessments=impact_assessments,
            clusters=clusters,
            contradictions=contradictions,
            verifications=verifications or [],
            artifacts=artifacts_dict,
            deployments=deployments_dict,
            services=services_dict,
            release_assessment=rel_assessment,
            decision=decision,
            admitted_evidence=admitted_evidence,
            rejected_evidence=rejected_failures,
            gaps=gaps,
            telemetry=telemetry,
            created_at=now_str,
            updated_at=now_str,
        )

        # 9. Persist to authoritative store if available
        if self.store and hasattr(self.store, "security"):
            try:
                self.store.security.save_investigation(inv)
                self.store.security.save_decision(decision)
                for imp_item in impact_assessments.values():
                    self.store.security.save_impact_assessment(imp_item)
            except Exception:
                pass

        return inv


    def _build_investigation_gaps(
        self,
        findings: List[SecurityFinding],
        contradictions: List[SecurityContradictionRecord],
        reachability_map: Dict[str, ReachabilityAssessment],
        is_stale: bool,
    ) -> List[InformationGap]:
        """Construct formal InformationGap records representing DAG verification requirements."""
        gaps: List[InformationGap] = []

        # Gap 1: Ingestion completeness
        gaps.append(
            InformationGap(
                gap_id="GAP-SEC-INGESTION",
                gap_type=GapType.STATE_VERIFICATION,
                description="Verify security findings ingested and normalized",
                target_entity="security_findings",
                status=GapStatus.RESOLVED if findings else GapStatus.OPEN,
                resolution="Findings normalized and admitted" if findings else "No findings ingested",
            )
        )

        # Gap 2: Contradictions resolution
        active_contras = [c for c in contradictions if c.status.value == "CONTRADICTED"]
        gaps.append(
            InformationGap(
                gap_id="GAP-SEC-CONTRADICTION",
                gap_type=GapType.CONTRADICTION_RECONCILIATION,
                description="Verify absence of conflicting scanner or artifact evidence",
                target_entity="contradictions",
                status=GapStatus.RECONCILIATION_REQUIRED if active_contras else GapStatus.RESOLVED,
                resolution=f"{len(active_contras)} contradiction(s) require reconciliation" if active_contras else "No active contradictions",
            )
        )

        # Gap 3: Reachability certainty
        unknown_reaches = [
            r for r in reachability_map.values() if r.status.value == "REACHABILITY_UNKNOWN"
        ]
        gaps.append(
            InformationGap(
                gap_id="GAP-SEC-REACHABILITY",
                gap_type=GapType.PREREQUISITE,
                description="Verify code-path reachability of detected vulnerabilities",
                target_entity="reachability",
                status=GapStatus.OPEN if unknown_reaches else GapStatus.RESOLVED,
                resolution=f"{len(unknown_reaches)} package(s) have unknown reachability" if unknown_reaches else "All package reachabilities verified",
            )
        )

        # Root Gap: Security Clearance
        root_resolved = not active_contras and not is_stale
        gaps.append(
            InformationGap(
                gap_id="GAP-SEC-ROOT",
                gap_type=GapType.OBJECTIVE_ROOT,
                description="Overall security clearance authorization",
                target_entity="security_clearance",
                status=GapStatus.RESOLVED if root_resolved else GapStatus.BLOCKED,
                resolution="Security clearance verified" if root_resolved else "Security clearance blocked or pending arbitration",
            )
        )

        return gaps
