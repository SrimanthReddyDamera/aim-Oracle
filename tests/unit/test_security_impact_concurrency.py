"""
ORACLE 4.8 — Security Impact Intelligence & Release Correlation
High-Concurrency & Multi-Tenant Scalability Suite

Section 20 Specifications:
- Test 10 concurrent, 25 concurrent, 50 concurrent, 100 concurrent security investigations.
- Verify zero cross-investigation leakage.
- Verify zero cross-tenant leakage.
- Verify zero duplicate authoritative decisions.
- Verify deterministic outcomes under randomized concurrent arrival order.
- Verify thread safety of clustering, impact chain construction, and policy evaluation.
"""

import random
import time
import pytest
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Any

from backend.release.security.models import (
    BuildArtifact,
    Deployment,
    DeploymentEnvironment,
    NetworkExposure,
    RuntimeService,
    SecurityDecisionOutcome,
    SecurityImpactLevel,
)
from backend.release.security.investigation import SecurityInvestigationEngine
from backend.release.security.clustering import SecurityClusteringEngine
from backend.release.security.impact import SecurityImpactEngine


@pytest.mark.parametrize("concurrency_level", [10, 25, 50, 100])
def test_concurrent_security_investigations_isolation_and_determinism(concurrency_level):
    """
    Execute 10, 25, 50, 100 concurrent security investigations across distinct tenants and repositories.
    Assert zero cross-tenant contamination, zero duplicate decisions, and 100% deterministic outcomes.
    """
    engine = SecurityInvestigationEngine(max_workers=4)

    def _run_single_investigation(idx: int) -> Dict[str, Any]:
        tenant_id = f"tenant-concurrent-{idx}"
        repo = f"org/service-{idx}"
        commit = f"commit-{idx:04d}"
        artifact_digest = f"sha256:art-{idx:064d}"
        
        # Alternate between a clean service and a vulnerable internet-facing service
        is_vulnerable = (idx % 2 == 0)
        
        service = RuntimeService(
            service_id=f"svc-{idx}",
            tenant_id=tenant_id,
            service_name=f"svc-app-{idx}",
            environment=DeploymentEnvironment.PRODUCTION,
            exposure=NetworkExposure.INTERNET_FACING if is_vulnerable else NetworkExposure.INTERNAL,
            active_routes=[f"/api/v1/route-{idx}"],
        )
        
        artifact = BuildArtifact(
            artifact_digest=artifact_digest,
            tenant_id=tenant_id,
            artifact_name=f"app:{idx}.0",
            repository=repo,
            commit=commit,
        )
        
        deployment = Deployment(
            deployment_id=f"dep-{idx}",
            tenant_id=tenant_id,
            service_id=service.service_id,
            environment=DeploymentEnvironment.PRODUCTION,
            artifact_digest=artifact_digest,
            commit=commit,
        )
        
        raw_findings = []
        call_graph = {}
        if is_vulnerable:
            raw_findings.append({
                "id": f"SEC-CVE-2026-{idx:04d}",
                "scanner": "snyk",
                "severity": "CRITICAL",
                "package": "vuln-dep",
                "vulnerable_functions": [f"vuln_fn_{idx}"],
                "cvss": 9.8,
            })
            call_graph = {
                f"/api/v1/route-{idx}": [f"vuln_fn_{idx}"],
            }
        
        inv = engine.investigate(
            repository=repo,
            commit=commit,
            tenant_id=tenant_id,
            artifact_digest=artifact_digest,
            raw_findings=raw_findings,
            call_graph=call_graph,
            registered_routes=[f"/api/v1/route-{idx}"],
            build_artifact=artifact,
            deployment=deployment,
            service=service,
        )
        
        return {
            "idx": idx,
            "tenant_id": tenant_id,
            "investigation_id": inv.investigation_id,
            "decision_id": inv.decision.decision_id if inv.decision else None,
            "outcome": inv.decision.outcome if inv.decision else None,
            "is_vulnerable": is_vulnerable,
            "findings_count": len(inv.findings),
            "findings": [f.finding_id for f in inv.findings],
        }

    start_time = time.time()
    results = []
    
    with ThreadPoolExecutor(max_workers=min(concurrency_level, 32)) as executor:
        futures = [executor.submit(_run_single_investigation, i) for i in range(concurrency_level)]
        for f in as_completed(futures):
            results.append(f.result())
            
    elapsed = time.time() - start_time
    print(f"Executed {concurrency_level} concurrent investigations in {elapsed:.2f}s (throughput: {concurrency_level / elapsed:.1f} inv/s)")

    # Verification 1: Exactly concurrency_level results returned
    assert len(results) == concurrency_level

    # Verification 2: Zero duplicate investigation IDs or decision IDs
    inv_ids = {r["investigation_id"] for r in results}
    dec_ids = {r["decision_id"] for r in results}
    assert len(inv_ids) == concurrency_level
    assert len(dec_ids) == concurrency_level

    # Verification 3: 100% Deterministic outcomes and zero cross-tenant leakage
    for r in results:
        idx = r["idx"]
        expected_tenant = f"tenant-concurrent-{idx}"
        assert r["tenant_id"] == expected_tenant
        
        if r["is_vulnerable"]:
            assert r["outcome"] == SecurityDecisionOutcome.SECURITY_BLOCKED
            assert r["findings_count"] == 1
            # Verify finding strictly belongs to this tenant index, zero cross contamination
            assert r["findings"] == [f"SEC-CVE-2026-{idx:04d}"]
        else:
            assert r["outcome"] == SecurityDecisionOutcome.SECURITY_CLEAR
            assert r["findings_count"] == 0
            assert r["findings"] == []


def test_concurrent_randomized_finding_ordering_determinism():
    """
    Test that randomizing the order of ingested findings produces identical deterministic decisions and impact levels.
    """
    engine = SecurityInvestigationEngine()
    
    def _create_findings_set():
        return [
            {
                "id": "SEC-A",
                "scanner": "snyk",
                "severity": "CRITICAL",
                "package": "pkg-a",
                "vulnerable_functions": ["fn_a"],
                "cvss": 9.8,
            },
            {
                "id": "SEC-B",
                "scanner": "trivy",
                "severity": "HIGH",
                "package": "pkg-b",
                "vulnerable_functions": ["fn_b"],
                "cvss": 7.5,
            },
            {
                "id": "SEC-C",
                "scanner": "semgrep",
                "severity": "LOW",
                "package": "pkg-c",
                "cvss": 3.0,
            }
        ]
    
    call_graph = {
        "/api/v1/checkout": ["fn_a"],
    }
    
    outcomes = []
    
    def _run_with_shuffled_order(trial_idx: int):
        f_list = _create_findings_set()
        random.shuffle(f_list)  # Randomized ingestion order
        
        service = RuntimeService(
            service_id="svc-pay",
            tenant_id="tenant-det",
            service_name="payments",
            exposure=NetworkExposure.INTERNET_FACING,
            active_routes=["/api/v1/checkout"],
        )
        inv = engine.investigate(
            repository="org/payments",
            commit="commit-det-1",
            tenant_id="tenant-det",
            raw_findings=f_list,
            call_graph=call_graph,
            registered_routes=["/api/v1/checkout"],
            service=service,
        )
        return inv.decision.outcome, inv.impact_assessments["SEC-A"].impact_level

    with ThreadPoolExecutor(max_workers=8) as executor:
        futures = [executor.submit(_run_with_shuffled_order, i) for i in range(20)]
        for f in as_completed(futures):
            outcomes.append(f.result())

    # Every run must produce exactly the same outcome and impact level
    first_outcome = outcomes[0]
    for oc in outcomes:
        assert oc == first_outcome
        assert oc[0] == SecurityDecisionOutcome.SECURITY_BLOCKED
        assert oc[1] == SecurityImpactLevel.CRITICAL_IMPACT
