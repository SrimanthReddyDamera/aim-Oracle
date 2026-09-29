"""
ORACLE 4.8 — Security Impact Intelligence & Release Correlation
End-to-End Realistic Scenarios Suite (Scenarios 1 through 14)

Verifies the 14 realistic enterprise scenarios defined in Section 19 of the specification.
"""

import hashlib
import time
import pytest
from typing import Dict, List, Any

from backend.evidence.models import Evidence
from backend.release.models import (
    ReleaseCandidate,
    ReleaseDecisionOutcome,
    RiskLevel,
)
from backend.release.decision import ReleaseDecisionEngine
from backend.release.investigation import ReleaseReadinessInvestigator
from backend.release.persistence.factory import PersistenceFactory
from backend.release.events.models import EnterpriseEvent, EnterpriseEventType
from backend.release.events.impact import InvestigationImpactAnalyzer
from backend.release.security.models import (
    BuildArtifact,
    Deployment,
    DeploymentEnvironment,
    NetworkExposure,
    RuntimeService,
    SecurityCategory,
    SecuritySeverity,
    SecurityDecision,
    SecurityDecisionOutcome,
    SecurityFinding,
    SecurityImpactLevel,
    BusinessImpactLevel,
    SecurityReleaseAssessment,
    SecurityVerification,
    SecurityVerificationStatus,
    ReachabilityStatus,
    ExploitabilityLevel,
    CompensatingControl,
    CompensatingControlType,
    ContradictionStatus,
    DependencyRelationship,
)
from backend.release.security.investigation import SecurityInvestigationEngine
from backend.release.security.exposure import RuntimeExposureEngine
from backend.release.security.business_impact import BusinessImpactEngine
from backend.release.security.impact import SecurityImpactEngine
from backend.release.security.verification import SecurityVerificationEngine
from backend.release.security.contradictions import SecurityContradictionEngine
from backend.release.security.policy import SecurityPolicyEngine
from backend.release.security.decision import SecurityDecisionEngine


def _make_test_evidence(evidence_id: str, content: str = "test content", metadata: Dict[str, Any] = None) -> Evidence:
    h = hashlib.sha256(content.encode("utf-8")).hexdigest()
    return Evidence(
        evidence_id=evidence_id,
        source_id="test-source",
        source_type="ci_pipeline",
        content=content,
        content_hash=h,
        source_path="ci/test.log",
        chunk_index=0,
        start_offset=0,
        end_offset=len(content.encode("utf-8")),
        created_at="2026-09-09T12:00:00Z",
        metadata=metadata or {},
    )


# -----------------------------------------------------------------------------
# SCENARIO 1: Critical reachable vulnerability in production internet-facing service
# -----------------------------------------------------------------------------
def test_scenario_01_critical_reachable_internet_facing_blocks_release():
    """
    Scenario 1: Critical reachable vulnerability in production internet-facing service.
    Expected: SECURITY_BLOCKED, RELEASE_BLOCKED.
    """
    sec_engine = SecurityInvestigationEngine()
    
    # 1. Construct explicit internet-facing production runtime service
    service = RuntimeService(
        service_id="svc-payment-api",
        tenant_id="tenant-acme",
        service_name="payment-api",
        environment=DeploymentEnvironment.PRODUCTION,
        exposure=NetworkExposure.INTERNET_FACING,
        active_routes=["/api/v1/checkout", "/api/v1/charge"],
    )
    
    # 2. Build artifact and deployment
    artifact = BuildArtifact(
        artifact_digest="sha256:art11111111111111111111111111111111111111111111111111111111111111111",
        tenant_id="tenant-acme",
        artifact_name="payment-api:1.4.0",
        repository="org/payments",
        commit="commit-aaa111",
        build_id="bld-001",
    )
    deployment = Deployment(
        deployment_id="dep-prod-payment-01",
        tenant_id="tenant-acme",
        service_id="svc-payment-api",
        environment=DeploymentEnvironment.PRODUCTION,
        artifact_digest=artifact.artifact_digest,
        commit="commit-aaa111",
    )
    
    # 3. Critical raw finding with reachable route in call graph
    raw_findings = [{
        "id": "SEC-CVE-2026-0001",
        "scanner": "snyk",
        "severity": "CRITICAL",
        "category": "SCA",
        "package": "jsonwebtoken",
        "vulnerable_functions": ["verify_token"],
        "cvss": 9.8,
        "cve": "CVE-2026-0001",
    }]
    
    # Call graph reaches vulnerable function from active route
    call_graph = {
        "/api/v1/charge": ["auth_middleware", "verify_token"],
        "auth_middleware": ["verify_token"],
    }
    
    # 4. Investigate security
    sec_inv = sec_engine.investigate(
        repository="org/payments",
        commit="commit-aaa111",
        tenant_id="tenant-acme",
        artifact_digest=artifact.artifact_digest,
        raw_findings=raw_findings,
        call_graph=call_graph,
        registered_routes=["/api/v1/charge"],
        build_artifact=artifact,
        deployment=deployment,
        service=service,
    )
    
    assert sec_inv.decision is not None
    assert sec_inv.decision.outcome == SecurityDecisionOutcome.SECURITY_BLOCKED
    assert sec_inv.impact_assessments is not None
    assert "SEC-CVE-2026-0001" in sec_inv.impact_assessments
    assert sec_inv.impact_assessments["SEC-CVE-2026-0001"].impact_level == SecurityImpactLevel.CRITICAL_IMPACT
    
    # 5. Release Investigation & Decision
    rc = ReleaseCandidate(
        release_id="rel-payment-1.4.0",
        tenant_id="tenant-acme",
        service_name="payment-api",
        version="1.4.0",
        repository="org/payments",
        commit="commit-aaa111",
        target_branch="main",
        artifact_digest=artifact.artifact_digest,
        deployment_id=deployment.deployment_id,
        service_id=service.service_id,
    )
    
    rel_investigator = ReleaseReadinessInvestigator(security_engine=sec_engine)
    rel_result = rel_investigator.investigate(
        candidate=rc,
        tenant_id="tenant-acme",
        build_artifact=artifact,
        deployment=deployment,
        runtime_service=service,
        raw_findings=raw_findings,
        call_graph=call_graph,
        registered_routes=["/api/v1/charge"],
    )
    
    assert rel_result.security_release_assessment is not None
    assert rel_result.security_release_assessment.blocks_release is True
    
    rel_dec_engine = ReleaseDecisionEngine()
    rel_decision = rel_dec_engine.evaluate_decision(
        investigation_result=rel_result,
        security_release_assessment=rel_result.security_release_assessment,
    )
    assert rel_decision.outcome == ReleaseDecisionOutcome.BLOCKED
    assert any("Security impact blocker" in b or "CRITICAL" in b for b in rel_decision.blockers)


# -----------------------------------------------------------------------------
# SCENARIO 2: Critical vulnerability but confirmed unreachable
# -----------------------------------------------------------------------------
def test_scenario_02_critical_unreachable_security_conditional():
    """
    Scenario 2: Critical vulnerability but confirmed unreachable.
    Expected: SECURITY_CONDITIONAL subject to configured policy.
    """
    sec_engine = SecurityInvestigationEngine()
    
    raw_findings = [{
        "id": "SEC-CVE-2026-0002",
        "scanner": "trivy",
        "severity": "CRITICAL",
        "category": "SCA",
        "package": "xml-parser",
        "vulnerable_functions": ["parse_untrusted_xml"],
        "cvss": 9.5,
    }]
    
    # Call graph and registered routes show no path to vulnerable function
    call_graph = {
        "/api/v1/status": ["get_system_status"],
    }
    
    sec_inv = sec_engine.investigate(
        repository="org/backend-service",
        commit="commit-bbb222",
        tenant_id="tenant-acme",
        raw_findings=raw_findings,
        call_graph=call_graph,
        registered_routes=["/api/v1/status"],
    )
    
    assert sec_inv.decision is not None
    assert sec_inv.decision.outcome == SecurityDecisionOutcome.SECURITY_CONDITIONAL
    assert sec_inv.reachability["SEC-CVE-2026-0002"].status == ReachabilityStatus.UNREACHABLE
    assert sec_inv.impact_assessments["SEC-CVE-2026-0002"].impact_level in (SecurityImpactLevel.LOW_IMPACT, SecurityImpactLevel.MODERATE_IMPACT)


# -----------------------------------------------------------------------------
# SCENARIO 3: Repository patched but production artifact vulnerable
# -----------------------------------------------------------------------------
def test_scenario_03_repository_patched_artifact_vulnerable_drift():
    """
    Scenario 3: Repository patched but production artifact vulnerable.
    Expected: ARTIFACT_DEPLOYMENT_MISMATCH / REPOSITORY_ARTIFACT_MISMATCH,
              SECURITY_BLOCKED / REQUIRES_RECONCILIATION.
    """
    sec_engine = SecurityInvestigationEngine()
    
    # Production deployment runs an older artifact with vulnerable commit
    vulnerable_digest = "sha256:vulnerable_digest_3333333333333333333333333333333333333333333333"
    prod_deployment = Deployment(
        deployment_id="dep-prod-web-01",
        tenant_id="tenant-acme",
        service_id="svc-web",
        environment=DeploymentEnvironment.PRODUCTION,
        artifact_digest=vulnerable_digest,
        commit="commit-old-vulnerable-333",
    )
    
    # Current repository commit is patched
    patched_repo_commit = "commit-new-patched-444"
    
    # Finding is bound to the vulnerable production artifact
    raw_findings = [{
        "id": "SEC-CVE-2026-0003",
        "scanner": "snyk",
        "severity": "CRITICAL",
        "category": "SCA",
        "package": "openssl",
        "artifact_digest": vulnerable_digest,
        "commit": "commit-old-vulnerable-333",
    }]
    
    sec_inv = sec_engine.investigate(
        repository="org/web-service",
        commit=patched_repo_commit,
        tenant_id="tenant-acme",
        artifact_digest=vulnerable_digest,
        raw_findings=raw_findings,
        deployment=prod_deployment,
    )
    
    assert sec_inv.decision is not None
    # Must NOT be SECURITY_CLEAR
    assert sec_inv.decision.outcome in (SecurityDecisionOutcome.SECURITY_BLOCKED, SecurityDecisionOutcome.SECURITY_RECONCILIATION_REQUIRED)
    
    # Must detect explicit mismatch / artifact drift contradiction
    drift_contras = [
        c for c in sec_inv.contradictions
        if "MISMATCH" in c.contradiction_type or "DRIFT" in c.contradiction_type or "ARTIFACT" in c.contradiction_type
    ]
    assert len(drift_contras) > 0


# -----------------------------------------------------------------------------
# SCENARIO 4: Repository vulnerable but production deployment is verified patched artifact
# -----------------------------------------------------------------------------
def test_scenario_04_repository_vulnerable_production_patched_deployment():
    """
    Scenario 4: Repository vulnerable (e.g. in test branch or HEAD) but production
    deployment is a verified patched artifact.
    Expected: Decision based on deployment context, not repository HEAD alone.
    """
    sec_engine = SecurityInvestigationEngine()
    
    patched_digest = "sha256:patched_prod_digest_444444444444444444444444444444444444444444444"
    prod_deployment = Deployment(
        deployment_id="dep-prod-worker-01",
        tenant_id="tenant-acme",
        service_id="svc-worker",
        environment=DeploymentEnvironment.PRODUCTION,
        artifact_digest=patched_digest,
        commit="commit-prod-clean-555",
    )
    
    # Finding exists only on repository HEAD (commit-head-vulnerable-666) with different artifact
    head_finding = [{
        "id": "SEC-CVE-2026-0004",
        "scanner": "trivy",
        "severity": "HIGH",
        "category": "SCA",
        "package": "tar",
        "commit": "commit-head-vulnerable-666",
        "artifact_digest": "sha256:different_head_digest_6666666666666666666666666666666666666666",
    }]
    
    # When investigating the production deployment context
    sec_inv = sec_engine.investigate(
        repository="org/worker-service",
        commit="commit-prod-clean-555",
        tenant_id="tenant-acme",
        artifact_digest=patched_digest,
        raw_findings=head_finding,
        deployment=prod_deployment,
    )
    
    # The finding does not bind to the production artifact digest
    assert sec_inv.decision.outcome != SecurityDecisionOutcome.SECURITY_BLOCKED


# -----------------------------------------------------------------------------
# SCENARIO 5: Scanner A says reachable; scanner B says unreachable
# -----------------------------------------------------------------------------
def test_scenario_05_scanner_reachability_contradiction():
    """
    Scenario 5: Scanner A says reachable; scanner B says unreachable.
    Expected: SECURITY_RECONCILIATION_REQUIRED.
    """
    contra_engine = SecurityContradictionEngine()
    
    # Two findings for the same vulnerability from different scanners with contradictory reachability claims
    finding_a = SecurityFinding(
        finding_id="SEC-SCANNER-A",
        scanner="semgrep",
        severity=SecuritySeverity.CRITICAL,
        category=SecurityCategory.SCA,
        repository="org/repo",
        commit="commit-c5",
        package="axios",
        cve="CVE-2026-0005",
        is_reachable=True,
        raw_payload={"reachability": "REACHABLE"},
    )
    finding_b = SecurityFinding(
        finding_id="SEC-SCANNER-B",
        scanner="snyk",
        severity=SecuritySeverity.CRITICAL,
        category=SecurityCategory.SCA,
        repository="org/repo",
        commit="commit-c5",
        package="axios",
        cve="CVE-2026-0005",
        is_reachable=False,
        raw_payload={"reachability": "UNREACHABLE"},
    )
    
    contras = contra_engine.detect_contradictions(
        findings=[finding_a, finding_b],
    )
    
    # Must explicitly detect reachability conflict
    reach_contras = [c for c in contras if c.conflict_type == "REACHABILITY_EVIDENCE_CONFLICT"]
    assert len(reach_contras) == 1
    assert reach_contras[0].status == ContradictionStatus.CONTRADICTED
    
    # Evaluate policy on this contradiction
    policy_engine = SecurityPolicyEngine()
    res = policy_engine.evaluate_policies(
        findings=[finding_a, finding_b],
        contradictions=contras,
    )
    assert res.outcome == SecurityDecisionOutcome.SECURITY_RECONCILIATION_REQUIRED


# -----------------------------------------------------------------------------
# SCENARIO 6: Security finding exists only in dev dependency
# -----------------------------------------------------------------------------
def test_scenario_06_dev_dependency_reduced_impact():
    """
    Scenario 6: Security finding exists only in dev dependency.
    Expected: Reduced impact according to policy.
    """
    sec_engine = SecurityInvestigationEngine()
    
    raw_findings = [{
        "id": "SEC-DEV-001",
        "scanner": "npm-audit",
        "severity": "CRITICAL",
        "category": "SCA",
        "package": "mocha",
        "cvss": 9.0,
    }]
    
    sec_inv = sec_engine.investigate(
        repository="org/frontend",
        commit="commit-dev-test-777",
        tenant_id="tenant-acme",
        raw_findings=raw_findings,
        dev_packages={"mocha", "jest", "eslint"},
    )
    
    assert sec_inv.decision is not None
    # Dev dependency must not block production as a critical runtime flaw
    assert sec_inv.decision.outcome != SecurityDecisionOutcome.SECURITY_BLOCKED
    assert sec_inv.impact_assessments is not None
    assert "SEC-DEV-001" in sec_inv.impact_assessments
    # Impact is downgraded to MODERATE or LOW
    assert sec_inv.impact_assessments["SEC-DEV-001"].impact_level in (SecurityImpactLevel.MODERATE_IMPACT, SecurityImpactLevel.LOW_IMPACT)


# -----------------------------------------------------------------------------
# SCENARIO 7: Transitive dependency vulnerability with two dependency paths
# -----------------------------------------------------------------------------
def test_scenario_07_transitive_dependency_path_preservation():
    """
    Scenario 7: Transitive dependency vulnerability with two dependency paths.
    Expected: Complete path preservation.
    """
    sec_engine = SecurityInvestigationEngine()
    
    # Transitive dependency 'lodash' reachable via two top-level packages: 'express' and 'winston'
    dep_graph = [
        {"parent_package": "service", "child_package": "express"},
        {"parent_package": "service", "child_package": "winston"},
        {"parent_package": "express", "child_package": "lodash"},
        {"parent_package": "winston", "child_package": "lodash"},
    ]
    
    raw_findings = [{
        "id": "SEC-TRANSITIVE-001",
        "scanner": "snyk",
        "severity": "HIGH",
        "category": "SCA",
        "package": "lodash",
        "version": "4.17.20",
    }]
    
    sec_inv = sec_engine.investigate(
        repository="org/api",
        commit="commit-paths-888",
        tenant_id="tenant-acme",
        raw_findings=raw_findings,
        dependency_graph=dep_graph,
    )
    
    assert "lodash" in sec_inv.dependencies
    dep_assessment = sec_inv.dependencies["lodash"]
    assert len(dep_assessment.dependency_paths) >= 2
    # Check paths preserved
    path_strs = [" -> ".join(p) for p in dep_assessment.dependency_paths]
    assert any("express" in p and "lodash" in p for p in path_strs)
    assert any("winston" in p and "lodash" in p for p in path_strs)


# -----------------------------------------------------------------------------
# SCENARIO 8: Remediation PR merged but production rescan remains vulnerable
# -----------------------------------------------------------------------------
def test_scenario_08_remediation_merged_but_rescan_vulnerable():
    """
    Scenario 8: Remediation PR merged but production rescan remains vulnerable.
    Expected: SECURITY_BLOCKED.
    """
    ver_engine = SecurityVerificationEngine()
    
    orig_finding = SecurityFinding(
        finding_id="SEC-ORIG-001",
        scanner="snyk",
        severity=SecuritySeverity.CRITICAL,
        category=SecurityCategory.SCA,
        package="urllib3",
        cve="CVE-2026-0008",
        tenant_id="tenant-acme",
        repository="org/fetcher",
        commit="commit-orig-100",
    )
    
    # Rescan still shows the vulnerability active
    rescan_finding = SecurityFinding(
        finding_id="SEC-RESCAN-001",
        scanner="snyk",
        severity=SecuritySeverity.CRITICAL,
        category=SecurityCategory.SCA,
        package="urllib3",
        cve="CVE-2026-0008",
        tenant_id="tenant-acme",
        repository="org/fetcher",
        commit="commit-fixed-200",
    )
    
    ver = ver_engine.verify_remediation(
        original_finding=orig_finding,
        fixed_commit="commit-fixed-200",
        rescan_findings=[rescan_finding],
        pr_merged=True,  # PR was merged, but vulnerability is still present!
        tenant_id="tenant-acme",
    )
    
    assert ver.status == SecurityVerificationStatus.STILL_VULNERABLE
    
    # Verification passed into policy engine must result in SECURITY_BLOCKED
    policy_engine = SecurityPolicyEngine()
    res = policy_engine.evaluate_policies(
        findings=[orig_finding],
        verifications=[ver],
    )
    assert res.outcome == SecurityDecisionOutcome.SECURITY_BLOCKED


# -----------------------------------------------------------------------------
# SCENARIO 9: Remediation produces new artifact and fresh clean scan against exact artifact
# -----------------------------------------------------------------------------
def test_scenario_09_fresh_clean_scan_exact_artifact_security_clear():
    """
    Scenario 9: Remediation produces a new artifact and fresh clean scan against exact artifact.
    Expected: SECURITY_CLEAR if all required evidence is valid.
    """
    ver_engine = SecurityVerificationEngine()
    
    new_clean_digest = "sha256:clean_artifact_digest_99999999999999999999999999999999999999999"
    
    orig_finding = SecurityFinding(
        finding_id="SEC-ORIG-009",
        scanner="trivy",
        severity=SecuritySeverity.CRITICAL,
        category=SecurityCategory.SCA,
        package="openssl",
        cve="CVE-2026-0009",
        tenant_id="tenant-acme",
        repository="org/crypto",
        commit="commit-vuln-900",
    )
    
    # Fresh scan on new artifact contains zero findings for CVE-2026-0009
    ver = ver_engine.verify_remediation(
        original_finding=orig_finding,
        fixed_commit="commit-patched-901",
        rescan_findings=[],
        rescan_artifact_digest=new_clean_digest,
        pr_merged=True,
        tenant_id="tenant-acme",
    )
    
    assert ver.status == SecurityVerificationStatus.VERIFIED_RESOLVED
    assert ver.rescan_artifact_digest == new_clean_digest
    
    # Now run investigation for the new artifact with no active findings
    sec_engine = SecurityInvestigationEngine()
    clean_artifact = BuildArtifact(
        artifact_digest=new_clean_digest,
        tenant_id="tenant-acme",
        artifact_name="crypto-service:2.0.0",
        repository="org/crypto",
        commit="commit-patched-901",
        build_id="bld-clean-901",
    )
    
    sec_inv = sec_engine.investigate(
        repository="org/crypto",
        commit="commit-patched-901",
        tenant_id="tenant-acme",
        artifact_digest=new_clean_digest,
        raw_findings=[],
        build_artifact=clean_artifact,
        verifications=[ver],
    )
    
    assert sec_inv.decision.outcome == SecurityDecisionOutcome.SECURITY_CLEAR


# -----------------------------------------------------------------------------
# SCENARIO 10: Security is clear but CI is failing
# -----------------------------------------------------------------------------
def test_scenario_10_security_clear_ci_failing_blocks_release():
    """
    Scenario 10: Security is clear but CI is failing.
    Expected: SECURITY_CLEAR, RELEASE_BLOCKED.
    """
    sec_engine = SecurityInvestigationEngine()
    
    rc = ReleaseCandidate(
        release_id="rel-backend-1.0.0",
        tenant_id="tenant-acme",
        service_name="backend",
        version="1.0.0",
        repository="org/backend",
        commit="commit-ci-fail-1010",
        target_branch="main",
        ci_run_id="ci-failed-run-999",
    )
    
    rel_investigator = ReleaseReadinessInvestigator(security_engine=sec_engine)
    
    ci_failure_evidence = _make_test_evidence(
        evidence_id="EV-CI-FAIL-001",
        content="CI pipeline failed",
        metadata={"status": "FAILED", "outcome": "failure", "commit": "commit-ci-fail-1010"},
    )
    
    rel_result = rel_investigator.investigate(
        candidate=rc,
        raw_findings=[],
        external_evidences=[ci_failure_evidence],
    )
    
    # Security must be clear
    assert rel_result.security_release_assessment is not None
    assert rel_result.security_release_assessment.outcome == SecurityDecisionOutcome.SECURITY_CLEAR
    assert rel_result.security_release_assessment.blocks_release is False
    
    # But release decision must be BLOCKED due to CI failure
    rel_dec_engine = ReleaseDecisionEngine()
    rel_dec = rel_dec_engine.evaluate_decision(
        candidate=rc,
        investigation_result=rel_result,
        security_release_assessment=rel_result.security_release_assessment,
    )
    
    assert rel_dec.outcome == ReleaseDecisionOutcome.BLOCKED
    assert any("CI" in b or "GAP-CI-VALIDATION" in b for b in rel_dec.blockers)


# -----------------------------------------------------------------------------
# SCENARIO 11: Security finding arrives while release investigation is running
# -----------------------------------------------------------------------------
def test_scenario_11_security_finding_arrives_triggers_targeted_reinvestigation():
    """
    Scenario 11: Security finding arrives while release investigation is running.
    Expected: Targeted DAG invalidation/reinvestigation.
    """
    rc = ReleaseCandidate(
        release_id="rel-active-1111",
        tenant_id="tenant-acme",
        service_name="payments",
        version="1.1.1",
        repository="org/payments",
        commit="commit-1111",
        target_branch="main",
    )
    
    # Initial investigation (clear)
    sec_engine = SecurityInvestigationEngine()
    rel_investigator = ReleaseReadinessInvestigator(security_engine=sec_engine)
    init_res = rel_investigator.investigate(candidate=rc, raw_findings=[])
    
    # New security finding event arrives
    evt = EnterpriseEvent(
        event_id="evt-sec-find-111",
        event_type=EnterpriseEventType.SECURITY_FINDING_CREATED,
        source="snyk",
        tenant_id="tenant-acme",
        repository="org/payments",
        commit="commit-1111",
        release_id="rel-active-1111",
        entity_id="SEC-FINDING-LATE-001",
    )
    
    # Handle event through InvestigationImpactAnalyzer
    analyzer = InvestigationImpactAnalyzer()
    impact_res = analyzer.analyze_impact(evt, candidate=rc, previous_result=init_res)
    
    assert impact_res is not None
    assert "GAP-SECURITY-SAST" in impact_res.affected_gap_ids or "GAP-SECURITY-SCA" in impact_res.affected_gap_ids
    assert impact_res.requires_reinvestigation is True


# -----------------------------------------------------------------------------
# SCENARIO 12: Same CVE simultaneously affects multiple repositories and tenants
# -----------------------------------------------------------------------------
def test_scenario_12_multi_tenant_multi_repo_isolation():
    """
    Scenario 12: Same CVE simultaneously affects multiple repositories and tenants.
    Expected: Complete isolation; decisions and state do not leak.
    """
    sec_engine = SecurityInvestigationEngine()
    
    cve_id = "CVE-2026-9999"
    
    # Tenant 1: Org Alpha, internet facing (CRITICAL)
    svc_alpha = RuntimeService(
        service_id="svc-alpha-web",
        tenant_id="tenant-alpha",
        service_name="alpha-web",
        environment=DeploymentEnvironment.PRODUCTION,
        exposure=NetworkExposure.INTERNET_FACING,
        active_routes=["/api/v1/public"],
    )
    raw_alpha = [{
        "id": "FINDING-ALPHA-1",
        "scanner": "snyk",
        "severity": "CRITICAL",
        "package": "common-lib",
        "cve": cve_id,
        "vulnerable_functions": ["exec_code"],
    }]
    call_alpha = {"/api/v1/public": ["exec_code"]}
    
    inv_alpha = sec_engine.investigate(
        repository="alpha/repo",
        commit="commit-alpha-1",
        tenant_id="tenant-alpha",
        raw_findings=raw_alpha,
        call_graph=call_alpha,
        registered_routes=["/api/v1/public"],
        service=svc_alpha,
    )
    
    # Tenant 2: Org Beta, internal batch worker (INTERNAL, UNREACHABLE)
    svc_beta = RuntimeService(
        service_id="svc-beta-worker",
        tenant_id="tenant-beta",
        service_name="beta-worker",
        environment=DeploymentEnvironment.PRODUCTION,
        exposure=NetworkExposure.INTERNAL,
        active_routes=[],
    )
    raw_beta = [{
        "id": "FINDING-BETA-1",
        "scanner": "trivy",
        "severity": "CRITICAL",
        "package": "common-lib",
        "cve": cve_id,
        "vulnerable_functions": ["exec_code"],
    }]
    call_beta = {"worker_task": ["batch_process"]}
    
    inv_beta = sec_engine.investigate(
        repository="beta/repo",
        commit="commit-beta-1",
        tenant_id="tenant-beta",
        raw_findings=raw_beta,
        call_graph=call_beta,
        service=svc_beta,
    )
    
    # Assert total isolation
    assert inv_alpha.tenant_id == "tenant-alpha"
    assert inv_beta.tenant_id == "tenant-beta"
    assert inv_alpha.decision.outcome == SecurityDecisionOutcome.SECURITY_BLOCKED
    assert inv_beta.decision.outcome in (SecurityDecisionOutcome.SECURITY_CONDITIONAL, SecurityDecisionOutcome.SECURITY_REQUIRES_REVIEW)
    assert inv_alpha.impact_assessments["FINDING-ALPHA-1"].impact_level == SecurityImpactLevel.CRITICAL_IMPACT
    assert inv_beta.impact_assessments["FINDING-BETA-1"].impact_level in (SecurityImpactLevel.MODERATE_IMPACT, SecurityImpactLevel.LOW_IMPACT, SecurityImpactLevel.HIGH_IMPACT)


# -----------------------------------------------------------------------------
# SCENARIO 13: Production exposure changes from internal to internet-facing
# -----------------------------------------------------------------------------
def test_scenario_13_runtime_exposure_change_invalidates_investigation():
    """
    Scenario 13: Production exposure changes from internal to internet-facing.
    Expected: Security investigation invalidation and decision reevaluation.
    """
    rc = ReleaseCandidate(
        release_id="rel-service-1313",
        tenant_id="tenant-acme",
        service_name="gateway",
        version="1.3.13",
        repository="org/svc-gateway",
        commit="commit-1313",
        target_branch="main",
        service_id="svc-gateway",
    )
    
    # Save active investigation
    sec_engine = SecurityInvestigationEngine()
    rel_investigator = ReleaseReadinessInvestigator(security_engine=sec_engine)
    init_res = rel_investigator.investigate(candidate=rc, raw_findings=[])
    
    # Exposure change event arrives
    evt = EnterpriseEvent(
        event_id="evt-exp-change-13",
        event_type=EnterpriseEventType.RUNTIME_EXPOSURE_CHANGED,
        source="k8s_ingress_controller",
        tenant_id="tenant-acme",
        service_id="svc-gateway",
        release_id="rel-service-1313",
        payload={"new_exposure": "INTERNET_FACING", "ingress_ip": "203.0.113.10"},
    )
    
    analyzer = InvestigationImpactAnalyzer()
    inval_res = analyzer.analyze_impact(evt, candidate=rc, previous_result=init_res)
    assert inval_res.requires_reinvestigation is True
    assert "GAP-SECURITY-SAST" in inval_res.affected_gap_ids or "GAP-SECURITY-SCA" in inval_res.affected_gap_ids


# -----------------------------------------------------------------------------
# SCENARIO 14: Security control/WAF evidence expires
# -----------------------------------------------------------------------------
def test_scenario_14_compensating_control_expiration():
    """
    Scenario 14: Security control/WAF evidence expires.
    Expected: Automatic reevaluation; finding without valid compensating control blocks release.
    """
    policy_engine = SecurityPolicyEngine()
    
    finding = SecurityFinding(
        finding_id="SEC-WAF-001",
        scanner="snyk",
        severity=SecuritySeverity.CRITICAL,
        category=SecurityCategory.SCA,
        package="log4j",
        cve="CVE-2021-44228",
        tenant_id="tenant-acme",
        repository="org/legacy",
        commit="commit-waf-1414",
        is_reachable=True,
    )
    
    # Control expired 1 hour ago
    expired_time = "2026-09-10T12:00:00Z"
    waf_control = CompensatingControl(
        control_id="ctrl-waf-01",
        name="WAF-Block-JNDI",
        control_type=CompensatingControlType.WAF,
        is_active=True,
        details={"valid_until": expired_time},
    )
    
    # Evaluate with compensating control marked valid_until in the past
    # The policy engine must reject expired controls
    res = policy_engine.evaluate_policies(
        findings=[finding],
        compensating_controls=[waf_control],
        is_evidence_stale=True,  # control evidence expired/stale
    )
    
    assert res.outcome in (
        SecurityDecisionOutcome.SECURITY_BLOCKED,
        SecurityDecisionOutcome.SECURITY_RECONCILIATION_REQUIRED,
        SecurityDecisionOutcome.SECURITY_INSUFFICIENT_EVIDENCE,
    )
