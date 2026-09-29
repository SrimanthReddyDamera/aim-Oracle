"""
ORACLE 4.8 — Security Impact Intelligence & Release Correlation
Persistence & Durable Recovery Verification Suite

Section 16 Test Specifications:
1. Persistence of Findings, Impact Assessments, Decisions, Verifications, Artifacts, Deployments, Runtime Services.
2. Crash & Restart Survival: Write to SQLite file on disk, close connection, re-open from path, verify full state recovery.
3. Multi-Tenant Isolation in Storage: Tenant A records are inaccessible to Tenant B.
"""

import os
import tempfile
import pytest

from backend.release.models import RiskLevel
from backend.release.persistence.factory import PersistenceFactory
from backend.release.security.models import (
    BuildArtifact,
    Deployment,
    DeploymentEnvironment,
    NetworkExposure,
    RuntimeService,
    SecurityCategory,
    SecurityFinding,
    SecuritySeverity,
    SecurityDecision,
    SecurityDecisionOutcome,
    SecurityImpactAssessment,
    SecurityImpactLevel,
    BusinessImpactLevel,
    SecurityVerification,
    SecurityVerificationStatus,
    ReachabilityStatus,
)
from backend.release.security.business_impact import BusinessImpactAssessment


@pytest.fixture
def temp_db_path():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    yield path
    try:
        if os.path.exists(path):
            os.remove(path)
    except Exception:
        pass


def test_durable_artifact_deployment_service_persistence(temp_db_path):
    """
    Test durable storage and reload of BuildArtifact, Deployment, and RuntimeService.
    """
    bundle = PersistenceFactory.create_bundle(database_url=temp_db_path)
    
    artifact = BuildArtifact(
        artifact_digest="sha256:art1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
        tenant_id="tenant-alpha",
        artifact_name="payments-api:2.1.0",
        repository="org/payments",
        commit="commit-c111",
        build_id="bld-111",
    )
    
    service = RuntimeService(
        service_id="svc-pay-01",
        tenant_id="tenant-alpha",
        service_name="payments-api",
        environment=DeploymentEnvironment.PRODUCTION,
        exposure=NetworkExposure.INTERNET_FACING,
        active_routes=["/checkout", "/pay"],
    )
    
    deployment = Deployment(
        deployment_id="dep-pay-prod-01",
        tenant_id="tenant-alpha",
        service_id="svc-pay-01",
        environment=DeploymentEnvironment.PRODUCTION,
        artifact_digest=artifact.artifact_digest,
        commit="commit-c111",
    )
    
    # Save all three
    assert bundle.artifacts.save_artifact(artifact) is True
    assert bundle.artifacts.save_runtime_service(service) is True
    assert bundle.artifacts.save_deployment(deployment) is True
    
    # Simulate process crash / database close
    bundle.pool.close()
    del bundle
    
    # Reconnect to disk file
    reopened = PersistenceFactory.create_bundle(database_url=temp_db_path)
    
    loaded_art = reopened.artifacts.get_artifact(artifact.artifact_digest, tenant_id="tenant-alpha")
    assert loaded_art is not None
    assert loaded_art.artifact_name == "payments-api:2.1.0"
    assert loaded_art.commit == "commit-c111"
    
    loaded_svc = reopened.artifacts.get_runtime_service(service.service_id, tenant_id="tenant-alpha")
    assert loaded_svc is not None
    assert loaded_svc.service_name == "payments-api"
    assert loaded_svc.exposure == NetworkExposure.INTERNET_FACING
    
    loaded_dep = reopened.artifacts.get_deployment(deployment.deployment_id, tenant_id="tenant-alpha")
    assert loaded_dep is not None
    assert loaded_dep.artifact_digest == artifact.artifact_digest
    assert loaded_dep.environment == DeploymentEnvironment.PRODUCTION

    reopened.pool.close()


def test_durable_security_finding_impact_decision_persistence(temp_db_path):
    """
    Test durable storage and reload of SecurityFinding, SecurityImpactAssessment, SecurityDecision, SecurityVerification.
    """
    bundle = PersistenceFactory.create_bundle(database_url=temp_db_path)
    
    finding = SecurityFinding(
        finding_id="SEC-FIND-999",
        scanner="snyk",
        category=SecurityCategory.SCA,
        severity=SecuritySeverity.CRITICAL,
        tenant_id="tenant-alpha",
        repository="org/payments",
        commit="commit-c111",
        artifact_digest="sha256:art999",
        package="jsonwebtoken",
        vulnerable_functions=["verify_jwt"],
        cve="CVE-2026-9999",
        cvss=9.8,
    )
    
    impact = SecurityImpactAssessment(
        assessment_id="secimp-999",
        finding_id="SEC-FIND-999",
        tenant_id="tenant-alpha",
        repository="org/payments",
        commit="commit-c111",
        artifact_digest="sha256:art999",
        package="jsonwebtoken",
        cve="CVE-2026-9999",
        impact_level=SecurityImpactLevel.CRITICAL_IMPACT,
        vulnerability_severity=SecuritySeverity.CRITICAL,
        reachability_status=ReachabilityStatus.CONFIRMED_REACHABLE,
        network_exposure=NetworkExposure.INTERNET_FACING,
        business_impact=BusinessImpactLevel.CRITICAL,
        rationale="Critical internet-facing reachable exploit in payments service",
        confidence=0.98,
    )
    
    decision = SecurityDecision(
        decision_id="secdec-999",
        tenant_id="tenant-alpha",
        repository="org/payments",
        commit="commit-c111",
        artifact_digest="sha256:art999",
        outcome=SecurityDecisionOutcome.SECURITY_BLOCKED,
        risk_level=RiskLevel.CRITICAL,
        confidence=0.99,
        deterministic_reason="Blocked due to critical reachable vulnerability in payments",
        blocking_factors=["Critical internet-facing vulnerability in jsonwebtoken"],
        verified_factors=[],
    )
    
    verification = SecurityVerification(
        verification_id="secver-999",
        finding_id="SEC-FIND-999",
        tenant_id="tenant-alpha",
        rescan_commit="commit-c222-fixed",
        rescan_artifact_digest="sha256:art999-fixed",
        status=SecurityVerificationStatus.VERIFIED_RESOLVED,
        notes="Clean rescan verified resolution on new artifact",
    )
    
    assert bundle.security.save_finding(finding) is True
    assert bundle.security.save_impact_assessment(impact) is True
    assert bundle.security.save_decision(decision) is True
    assert bundle.security.save_verification(verification) is True
    
    # Simulate restart
    bundle.pool.close()
    del bundle
    reopened = PersistenceFactory.create_bundle(database_url=temp_db_path)
    
    retrieved_f = reopened.security.get_finding("SEC-FIND-999", tenant_id="tenant-alpha")
    assert retrieved_f is not None
    assert retrieved_f.cve == "CVE-2026-9999"
    assert retrieved_f.severity == SecuritySeverity.CRITICAL
    
    retrieved_imp = reopened.security.get_impact_assessment("secimp-999", tenant_id="tenant-alpha")
    assert retrieved_imp is not None
    assert retrieved_imp.impact_level == SecurityImpactLevel.CRITICAL_IMPACT
    assert retrieved_imp.reachability_status == ReachabilityStatus.CONFIRMED_REACHABLE
    
    retrieved_dec = reopened.security.get_decision("secdec-999", tenant_id="tenant-alpha")
    assert retrieved_dec is not None
    assert retrieved_dec.outcome == SecurityDecisionOutcome.SECURITY_BLOCKED
    
    retrieved_ver = reopened.security.get_verification("secver-999", tenant_id="tenant-alpha")
    assert retrieved_ver is not None
    assert retrieved_ver.status == SecurityVerificationStatus.VERIFIED_RESOLVED

    reopened.pool.close()


def test_persistence_tenant_isolation(temp_db_path):
    """
    Ensure complete storage boundary isolation: Tenant B cannot read Tenant A's security entities.
    """
    bundle = PersistenceFactory.create_bundle(database_url=temp_db_path)
    
    finding = SecurityFinding(
        finding_id="SEC-SECRET-001",
        scanner="gitleaks",
        category=SecurityCategory.SECRETS,
        severity=SecuritySeverity.CRITICAL,
        tenant_id="tenant-acme",
        repository="org/acme-core",
        commit="commit-acme-1",
        description="Leaked production AWS key",
    )
    bundle.security.save_finding(finding)
    
    # Accessible to tenant-acme
    assert bundle.security.get_finding("SEC-SECRET-001", tenant_id="tenant-acme") is not None
    
    # Inaccessible to tenant-foreign
    assert bundle.security.get_finding("SEC-SECRET-001", tenant_id="tenant-foreign") is None
    
    # List findings isolated by tenant
    acme_list = bundle.security.list_findings(tenant_id="tenant-acme")
    foreign_list = bundle.security.list_findings(tenant_id="tenant-foreign")
    
    assert any(f.finding_id == "SEC-SECRET-001" for f in acme_list)
    assert not any(f.finding_id == "SEC-SECRET-001" for f in foreign_list)

    bundle.pool.close()
