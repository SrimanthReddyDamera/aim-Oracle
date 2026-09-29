"""
Security Impact Intelligence Engine & Attack-Path Chain Builder (Brick 4.8)

Answers the central ORACLE 4.8 question:
"Does this security finding actually affect this exact release/deployment?"

Evaluates multi-dimensional evidence:
1. Vulnerability metrics (severity, CVSS, EPSS, KEV, exploit availability).
2. Dependency impact (direct vs transitive, scope runtime vs dev, exact version).
3. Code reachability (confirmed route/entrypoint vs dead code vs lexical-only rejection).
4. Runtime exposure (internet-facing vs internal, auth requirements, compensating controls).
5. Deployment binding (exact artifact digest, deployed version, artifact drift).
6. Business & operational impact (criticality tier, transaction paths, active incidents).
7. Epistemic evidence state (freshness, contradiction, confidence).

Constructs an evidence-backed, structured ImpactChain with provenance on every edge.
"""

from __future__ import annotations

import time
import uuid
from typing import Any, Dict, List, Optional, Set

from backend.release.models import ReleaseCandidate
from backend.release.security.business_impact import BusinessImpactAssessment
from backend.release.security.exposure import RuntimeExposureAssessment
from backend.release.security.models import (
    AffectedDependency,
    AuthRequirement,
    BuildArtifact,
    BusinessImpactLevel,
    DependencyRelationType,
    DependencyScope,
    Deployment,
    DeploymentEnvironment,
    ExploitabilityAssessment,
    ImpactChain,
    ImpactChainEdge,
    ImpactChainNode,
    NetworkExposure,
    ReachabilityAssessment,
    ReachabilityStatus,
    RuntimeService,
    SecurityFinding,
    SecurityImpactAssessment,
    SecurityImpactLevel,
    SecuritySeverity,
)


class SecurityImpactEngine:
    """
    Deterministic security impact evaluator and attack-path constructor.
    """

    def evaluate_impact(
        self,
        finding: SecurityFinding,
        dependency: Optional[AffectedDependency] = None,
        reachability: Optional[ReachabilityAssessment] = None,
        exposure: Optional[RuntimeExposureAssessment] = None,
        business_impact: Optional[BusinessImpactAssessment] = None,
        artifact: Optional[BuildArtifact] = None,
        deployment: Optional[Deployment] = None,
        service: Optional[RuntimeService] = None,
        candidate: Optional[ReleaseCandidate] = None,
        exploitability: Optional[ExploitabilityAssessment] = None,
        is_evidence_stale: bool = False,
        has_contradictions: bool = False,
    ) -> SecurityImpactAssessment:
        """
        Execute deterministic multi-dimensional impact analysis.
        """
        assessment_id = f"secimp-{uuid.uuid4().hex[:8]}"
        tenant_id = finding.tenant_id or "default"
        repo = finding.repository
        commit = candidate.commit if candidate else finding.commit
        artifact_digest = (
            artifact.artifact_digest
            if artifact
            else (deployment.artifact_digest if deployment else (finding.artifact_digest or (candidate.artifact_digest if candidate else None)))
        )
        deployment_id = deployment.deployment_id if deployment else (candidate.deployment_id if candidate else None)
        service_id = service.service_id if service else (candidate.service_id if candidate else None)

        env = deployment.environment if deployment else (service.environment if service else DeploymentEnvironment.PRODUCTION)

        # 1. Dependency Analysis
        is_runtime = True
        is_transitive = False
        dep_scope = DependencyScope.RUNTIME
        if dependency:
            is_runtime = dependency.scope == DependencyScope.RUNTIME
            is_transitive = dependency.relation_type == DependencyRelationType.TRANSITIVE
            dep_scope = dependency.scope

        # 2. Reachability Analysis
        reach_status = reachability.status if reachability else ReachabilityStatus.REACHABILITY_UNKNOWN

        # 3. Exposure & Auth Analysis
        net_exposure = exposure.exposure if exposure else NetworkExposure.UNKNOWN
        auth_req = exposure.auth_requirement if exposure else AuthRequirement.UNKNOWN

        # 4. Artifact & Deployment Binding: Detect Artifact Drift
        artifact_is_vulnerable = True
        artifact_drift = False

        if artifact and artifact.dependencies:
            # Check if package version in exact artifact matches vulnerable or fixed version
            pkg_name = finding.package
            if pkg_name and pkg_name in artifact.dependencies:
                installed_in_art = artifact.dependencies[pkg_name]
                if finding.fixed_version and installed_in_art == finding.fixed_version:
                    artifact_is_vulnerable = False
                elif artifact.is_vulnerable is False:
                    artifact_is_vulnerable = False

        # If repo HEAD is fixed but artifact is still vulnerable -> drift
        if finding.status.value == "RESOLVED" and artifact_is_vulnerable and artifact is not None:
            artifact_drift = True
        elif finding.status.value == "ACTIVE" and not artifact_is_vulnerable:
            artifact_drift = True

        # 5. Business Impact
        bus_level = business_impact.impact_level if business_impact else BusinessImpactLevel.UNKNOWN

        # 6. Multi-dimensional Impact Level Computation
        # INVARIANT: Do NOT map CVSS directly to impact!
        rationale_parts: List[str] = []
        conf = 1.0

        if is_evidence_stale:
            impact_level = SecurityImpactLevel.UNKNOWN_IMPACT
            rationale_parts.append("Security evidence is stale; impact cannot be authoritatively determined.")
            conf = 0.5
        elif not artifact_is_vulnerable:
            # Artifact is proven clean even if repository HEAD or another build is vulnerable
            impact_level = SecurityImpactLevel.NEGLIGIBLE_IMPACT
            rationale_parts.append(
                f"Artifact {artifact_digest[:12] if artifact_digest else 'target'} does not contain vulnerable version of {finding.package or finding.cve}."
            )
        elif reach_status == ReachabilityStatus.UNREACHABLE:
            # Vulnerability code is provably unreachable / dead code
            impact_level = SecurityImpactLevel.NEGLIGIBLE_IMPACT if dep_scope == DependencyScope.DEV else SecurityImpactLevel.LOW_IMPACT
            rationale_parts.append("Vulnerability confirmed unreachable via static call-graph trace.")
        elif dep_scope in (DependencyScope.DEV, DependencyScope.TEST) and net_exposure != NetworkExposure.INTERNET_FACING:
            # Dev dependency with no internet exposure
            impact_level = SecurityImpactLevel.LOW_IMPACT
            rationale_parts.append(f"Vulnerability isolated to {dep_scope.value} dependency with no external runtime exposure.")
        elif reach_status == ReachabilityStatus.CONFIRMED_REACHABLE and net_exposure == NetworkExposure.INTERNET_FACING:
            # Reachable + Internet Facing
            if finding.severity in (SecuritySeverity.CRITICAL, SecuritySeverity.HIGH):
                impact_level = SecurityImpactLevel.CRITICAL_IMPACT
                rationale_parts.append("Critical threat: Confirmed reachable vulnerability exposed on internet-facing route.")
            else:
                impact_level = SecurityImpactLevel.HIGH_IMPACT
                rationale_parts.append(f"{finding.severity.value} vulnerability confirmed reachable and internet-facing.")
        elif reach_status == ReachabilityStatus.CONFIRMED_REACHABLE and net_exposure == NetworkExposure.INTERNAL:
            if finding.severity == SecuritySeverity.CRITICAL:
                impact_level = SecurityImpactLevel.HIGH_IMPACT
            else:
                impact_level = SecurityImpactLevel.MODERATE_IMPACT
            rationale_parts.append("Confirmed reachable vulnerability in internal service.")
        elif reach_status == ReachabilityStatus.REACHABILITY_UNKNOWN:
            if finding.severity == SecuritySeverity.CRITICAL and net_exposure == NetworkExposure.INTERNET_FACING:
                impact_level = SecurityImpactLevel.HIGH_IMPACT
                rationale_parts.append("Critical vulnerability on internet-facing service with unverified code reachability.")
                conf = 0.75
            elif finding.severity in (SecuritySeverity.CRITICAL, SecuritySeverity.HIGH):
                impact_level = SecurityImpactLevel.MODERATE_IMPACT
                rationale_parts.append(f"Unverified reachability for {finding.severity.value} finding.")
                conf = 0.8
            else:
                impact_level = SecurityImpactLevel.LOW_IMPACT
                rationale_parts.append(f"Low/Medium vulnerability with unknown reachability.")
        else:
            impact_level = SecurityImpactLevel.MODERATE_IMPACT
            rationale_parts.append(f"Standard contextual impact for {finding.severity.value} finding.")

        # Mitigate if active compensating controls exist
        active_ctrls = exposure.active_controls if exposure else []
        if active_ctrls and impact_level in (SecurityImpactLevel.CRITICAL_IMPACT, SecurityImpactLevel.HIGH_IMPACT):
            ctrl_names = [c.name for c in active_ctrls if c.is_active]
            if ctrl_names:
                impact_level = SecurityImpactLevel.MODERATE_IMPACT if impact_level == SecurityImpactLevel.HIGH_IMPACT else SecurityImpactLevel.HIGH_IMPACT
                rationale_parts.append(f" Partially mitigated by active compensating control(s): {', '.join(ctrl_names)}.")

        # 7. Construct Evidence-Backed Impact Chain
        impact_chain = self._build_impact_chain(
            finding=finding,
            dependency=dependency,
            reachability=reachability,
            exposure=exposure,
            service=service,
            deployment=deployment,
            candidate=candidate,
        )

        evidence_refs: List[str] = list(finding.evidence_ids)
        if reachability:
            evidence_refs.extend(reachability.evidence_ids)
        if exposure:
            evidence_refs.extend(exposure.evidence_references)
        if business_impact:
            evidence_refs.extend(business_impact.evidence_references)

        return SecurityImpactAssessment(
            assessment_id=assessment_id,
            finding_id=finding.finding_id,
            tenant_id=tenant_id,
            repository=repo,
            commit=commit,
            artifact_digest=artifact_digest,
            deployment_id=deployment_id,
            service_id=service_id,
            environment=env,
            impact_level=impact_level,
            business_impact=bus_level,
            vulnerability_severity=finding.severity,
            cvss=finding.cvss,
            epss=exploitability.score if exploitability else None,
            known_exploited=finding.provenance.get("known_exploited", False),
            reachability_status=reach_status,
            network_exposure=net_exposure,
            auth_requirement=auth_req,
            is_runtime_dependency=is_runtime,
            is_transitive=is_transitive,
            dependency_scope=dep_scope,
            artifact_is_vulnerable=artifact_is_vulnerable,
            artifact_drift_detected=artifact_drift,
            impact_chain=impact_chain,
            rationale=" ".join(rationale_parts),
            evidence_references=list(set(evidence_refs)),
            confidence=conf,
            assessed_at="2026-09-09T12:00:00Z",
        )

    def _build_impact_chain(
        self,
        finding: SecurityFinding,
        dependency: Optional[AffectedDependency],
        reachability: Optional[ReachabilityAssessment],
        exposure: Optional[RuntimeExposureAssessment],
        service: Optional[RuntimeService],
        deployment: Optional[Deployment],
        candidate: Optional[ReleaseCandidate],
    ) -> ImpactChain:
        """
        Build an evidence-backed impact chain.
        Every edge must have explicit provenance. Never create edges merely from token sharing.
        """
        nodes: List[ImpactChainNode] = []
        edges: List[ImpactChainEdge] = []

        # Node 1: CVE
        cve_id = finding.cve or finding.finding_id
        nodes.append(ImpactChainNode(node_id=cve_id, node_type="CVE", label=cve_id, properties={"severity": finding.severity.value}))

        # Node 2: Vulnerable Package
        if finding.package:
            pkg_id = f"pkg:{finding.package}"
            nodes.append(ImpactChainNode(node_id=pkg_id, node_type="PACKAGE", label=finding.package, properties={"version": finding.current_version or ""}))
            edges.append(ImpactChainEdge(from_node_id=cve_id, to_node_id=pkg_id, relationship="AFFECTS", provenance=f"scanner:{finding.scanner}"))

            # Node 3: Dependency Path
            if dependency and dependency.dependency_paths:
                primary_path = dependency.dependency_paths[0]
                path_str = " -> ".join(primary_path)
                path_id = f"path:{dependency.package_name}"
                nodes.append(ImpactChainNode(node_id=path_id, node_type="DEPENDENCY_PATH", label=path_str, properties={"depth": len(primary_path)}))
                edges.append(ImpactChainEdge(from_node_id=pkg_id, to_node_id=path_id, relationship="DEPENDS_ON", provenance="manifest_lockfile_analysis"))
                last_node = path_id
            else:
                last_node = pkg_id

            # Node 4: Vulnerable Symbol / Function
            if reachability and reachability.vulnerable_symbol:
                sym_id = f"sym:{reachability.vulnerable_symbol}"
                nodes.append(ImpactChainNode(node_id=sym_id, node_type="VULNERABLE_FUNCTION", label=reachability.vulnerable_symbol, properties={"code_path": reachability.code_path}))
                edges.append(ImpactChainEdge(from_node_id=last_node, to_node_id=sym_id, relationship="CALLS", provenance="call_graph_analysis"))
                last_node = sym_id

            # Node 5: HTTP Route / Entry Point
            if reachability and (reachability.entry_point or reachability.route):
                rt = reachability.entry_point or reachability.route
                rt_id = f"route:{rt}"
                nodes.append(ImpactChainNode(node_id=rt_id, node_type="ROUTE", label=rt, properties={"status": reachability.status.value}))
                edges.append(ImpactChainEdge(from_node_id=last_node, to_node_id=rt_id, relationship="REACHABLE_FROM", provenance="route_trace_analysis"))
                last_node = rt_id

            # Node 6: Runtime Service
            if service:
                svc_id = f"svc:{service.service_id}"
                nodes.append(ImpactChainNode(node_id=svc_id, node_type="RUNTIME_SERVICE", label=service.service_name, properties={"tier": service.criticality_tier}))
                edges.append(ImpactChainEdge(from_node_id=last_node, to_node_id=svc_id, relationship="RUNS_AS", provenance="service_registry"))
                last_node = svc_id

            # Node 7: Production Deployment
            if deployment:
                dep_id = f"dep:{deployment.deployment_id}"
                nodes.append(ImpactChainNode(node_id=dep_id, node_type="DEPLOYMENT", label=deployment.deployment_id, properties={"digest": deployment.artifact_digest}))
                edges.append(ImpactChainEdge(from_node_id=last_node, to_node_id=dep_id, relationship="DEPLOYED_AS", provenance="deployment_manifest"))
                last_node = dep_id

            # Node 8: Network Exposure
            if exposure and exposure.exposure != NetworkExposure.UNKNOWN:
                exp_id = f"exp:{exposure.exposure.value}"
                nodes.append(ImpactChainNode(node_id=exp_id, node_type="EXPOSURE", label=exposure.exposure.value, properties={"auth": exposure.auth_requirement.value}))
                edges.append(ImpactChainEdge(from_node_id=last_node, to_node_id=exp_id, relationship="EXPOSED_BY", provenance="network_exposure_engine"))
                last_node = exp_id

            # Node 9: Release Candidate
            if candidate:
                rel_id = f"rel:{candidate.release_id}"
                nodes.append(ImpactChainNode(node_id=rel_id, node_type="RELEASE", label=f"{candidate.service_name} {candidate.version}", properties={"commit": candidate.commit}))
                edges.append(ImpactChainEdge(from_node_id=last_node, to_node_id=rel_id, relationship="REPRESENTS", provenance="release_correlator"))

        chain_summary = " -> ".join([n.label for n in nodes])
        return ImpactChain(finding_id=finding.finding_id, nodes=nodes, edges=edges, summary=chain_summary)
