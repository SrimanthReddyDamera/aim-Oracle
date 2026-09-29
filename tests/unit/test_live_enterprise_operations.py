"""
Unit and Integration Test Suite for ORACLE 4.5 — Live Enterprise Operations & Distributed Control Plane

Validates:
1. Webhook registration lifecycle & durable persistence (GitHub, Jira, InMemory).
2. Distributed locking with monotonic fencing tokens & safe stale recovery.
3. Multi-node worker dispatch, duplicate claim suppression & dead node lease recovery.
4. Adversarial multi-tenant boundary isolation (reads, writes, entity resolution, graph, replay).
5. Hardened HTTP public ingress, proxy headers, HMAC verification, payload limits & 202 ACK.
6. Separated health endpoints (/health/live, /health/ready, /health/dependencies) and Prometheus metrics (/metrics).
7. Operator CLI commands and controlled administrative replay with zero duplicate actions.
8. Provider verification harness & explicit capability classification matrix.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
import uuid
import pytest
from fastapi.testclient import TestClient

from backend.release.connectivity.credentials import CredentialProvider, EnvCredentialProvider
from backend.release.connectivity.verification import (
    CapabilityStatus,
    PilotExecutionMode,
    ProviderVerificationHarness,
)
from backend.release.connectivity.webhooks import (
    GitHubWebhookRegistrationProvider,
    InMemoryWebhookRegistrationProvider,
    JiraWebhookRegistrationProvider,
    WebhookDeliveryVerifier,
    WebhookRegistration,
    WebhookRegistrationService,
    WebhookRegistrationStatus,
)
from backend.release.distributed.coordinator import (
    DistributedWorkerCoordinator,
    NodeStatus,
    WorkerNode,
)
from backend.release.distributed.lock import (
    DatabaseDistributedLockProvider,
    DistributedLockProvider,
    InMemoryDistributedLockProvider,
    LockToken,
)
from backend.release.events.graph import EvidenceGraph, GraphEdgeType, GraphNodeType
from backend.release.events.models import DecisionChangeEvent, EnterpriseEvent, EnterpriseEventType
from backend.release.events.resolver import DeterministicEntityResolver
from backend.release.events.router import EventRouter
from backend.release.ingress import create_ingress_app
from backend.release.models import (
    GovernedActionProposal,
    GovernedActionStatus,
    GovernedActionType,
    ReleaseCandidate,
    ReleaseDecision,
    ReleaseDecisionOutcome,
    RiskLevel,
)
from backend.release.observability.metrics import GLOBAL_METRICS
from backend.release.persistence.factory import DurableStoreBundle, PersistenceFactory
from backend.release.cli import OracleCLI


@pytest.fixture
def clean_bundle() -> DurableStoreBundle:
    """Create fresh isolated in-memory persistence bundle."""
    return PersistenceFactory.create_bundle(in_memory=True)


# =============================================================================
# 1. WEBHOOK REGISTRATION LIFECYCLE & PERSISTENCE TESTS
# =============================================================================

def test_webhook_registration_full_lifecycle(clean_bundle):
    """Test DISCOVER -> VALIDATE -> REGISTER -> VERIFY -> ACTIVE -> DISABLE -> REMOVE."""
    service = WebhookRegistrationService(clean_bundle.webhooks)

    # 1. Registration
    reg = service.register(
        provider_name="mock",
        target_entity="enterprise/payment-gateway",
        callback_url="https://oracle.enterprise.internal/api/v1/events/mock",
        event_types=["push", "release"],
        tenant_id="tenant-alpha",
    )
    assert reg.registration_id.startswith("wh-reg-")
    assert reg.status == WebhookRegistrationStatus.ACTIVE
    assert reg.tenant_id == "tenant-alpha"
    assert reg.last_verified_at is not None

    # 2. Persistence retrieval
    fetched = clean_bundle.webhooks.get_registration(reg.registration_id, tenant_id="tenant-alpha")
    assert fetched is not None
    assert fetched.target_entity == "enterprise/payment-gateway"
    assert fetched.callback_url == "https://oracle.enterprise.internal/api/v1/events/mock"

    # 3. Disable
    disabled = service.disable(reg.registration_id, tenant_id="tenant-alpha")
    assert disabled is True
    fetched_disabled = clean_bundle.webhooks.get_registration(reg.registration_id, tenant_id="tenant-alpha")
    assert fetched_disabled.status == WebhookRegistrationStatus.DISABLED

    # 4. Re-verify to reactivate
    verified = service.verify(reg.registration_id, tenant_id="tenant-alpha")
    assert verified is True
    assert clean_bundle.webhooks.get_registration(reg.registration_id, tenant_id="tenant-alpha").status == WebhookRegistrationStatus.ACTIVE

    # 5. Remove
    removed = service.remove(reg.registration_id, tenant_id="tenant-alpha")
    assert removed is True
    fetched_removed = clean_bundle.webhooks.get_registration(reg.registration_id, tenant_id="tenant-alpha")
    assert fetched_removed.status == WebhookRegistrationStatus.REMOVED


def test_webhook_registration_validation_and_idempotency(clean_bundle):
    """Test callback URL validation and idempotent registration."""
    service = WebhookRegistrationService(clean_bundle.webhooks)

    # Invalid URL scheme
    with pytest.raises(ValueError, match="Invalid callback URL"):
        service.register(
            provider_name="mock",
            target_entity="enterprise/repo",
            callback_url="ftp://invalid.url",
            tenant_id="default",
        )

    # Idempotent registration returns existing active record
    reg1 = service.register(
        provider_name="mock",
        target_entity="enterprise/auth-service",
        callback_url="https://oracle.internal/api/v1/events/mock",
        tenant_id="tenant-beta",
    )
    reg2 = service.register(
        provider_name="mock",
        target_entity="enterprise/auth-service",
        callback_url="https://oracle.internal/api/v1/events/mock",
        tenant_id="tenant-beta",
    )
    assert reg1.registration_id == reg2.registration_id


def test_webhook_delivery_verifier():
    """Verify HMAC signature and replay window validation."""
    secret = "secret-key-12345"
    payload = b'{"action":"push","repository":{"name":"test-repo"}}'
    sig = "sha256=" + hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).hexdigest()
    now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    headers = {
        "x-hub-signature-256": sig,
        "x-timestamp": now_iso,
    }
    verifier = WebhookDeliveryVerifier()
    assert verifier.verify_delivery(payload, headers, secret, provider="github") is True

    # Bad secret fails
    assert verifier.verify_delivery(payload, headers, "wrong-secret", provider="github") is False


# =============================================================================
# 2. DISTRIBUTED LOCKING & FENCING TOKEN TESTS
# =============================================================================

def test_distributed_lock_fencing_tokens():
    """Test monotonic fencing token increments and owner exclusivity."""
    lock_provider = InMemoryDistributedLockProvider()

    token1 = lock_provider.acquire(key="investigation:rel-100", owner="worker-1", ttl_seconds=10.0, tenant_id="tenant-1")
    assert token1 is not None
    assert token1.fencing_token == 1
    assert token1.owner == "worker-1"

    # Concurrent worker cannot acquire
    token2 = lock_provider.acquire(key="investigation:rel-100", owner="worker-2", ttl_seconds=10.0, tenant_id="tenant-1")
    assert token2 is None

    # Idempotent re-acquisition by same owner preserves token
    token1_reacquire = lock_provider.acquire(key="investigation:rel-100", owner="worker-1", ttl_seconds=10.0, tenant_id="tenant-1")
    assert token1_reacquire is not None
    assert token1_reacquire.fencing_token == 1

    # Safe release
    released = lock_provider.release(token1)
    assert released is True

    # Next acquire gets strictly incremented fencing token
    token3 = lock_provider.acquire(key="investigation:rel-100", owner="worker-2", ttl_seconds=10.0, tenant_id="tenant-1")
    assert token3 is not None
    assert token3.fencing_token == 2
    assert token3.owner == "worker-2"


def test_database_distributed_lock_provider(clean_bundle):
    """Test database-backed distributed locking implementation."""
    lock_provider = DatabaseDistributedLockProvider(clean_bundle.locks)

    token_a = lock_provider.acquire(key="release:rel-200", owner="node-a", ttl_seconds=5.0, tenant_id="tenant-a")
    assert token_a is not None
    assert token_a.fencing_token == 1
    assert token_a.owner == "node-a"

    # Conflicting node cannot acquire
    token_b = lock_provider.acquire(key="release:rel-200", owner="node-b", ttl_seconds=5.0, tenant_id="tenant-a")
    assert token_b is None

    # Renewal succeeds
    renewed = lock_provider.renew(token_a, ttl_seconds=10.0)
    assert renewed is True

    # Safe release
    released = lock_provider.release(token_a)
    assert released is True

    # New acquisition gets next fencing token
    token_c = lock_provider.acquire(key="release:rel-200", owner="node-b", ttl_seconds=5.0, tenant_id="tenant-a")
    assert token_c is not None
    assert token_c.fencing_token == 2


def test_stale_worker_lock_rejection():
    """Verify expired/superseded worker token cannot mutate or renew."""
    lock_provider = InMemoryDistributedLockProvider()

    # Worker 1 acquires lock with short TTL
    token_stale = lock_provider.acquire(key="task-999", owner="worker-slow", ttl_seconds=0.01, tenant_id="default")
    assert token_stale is not None

    time.sleep(0.02)  # Allow expiration
    assert token_stale.is_expired is True

    # Worker 2 acquires the expired lock
    token_active = lock_provider.acquire(key="task-999", owner="worker-fast", ttl_seconds=10.0, tenant_id="default")
    assert token_active is not None
    assert token_active.fencing_token == 2

    # Stale worker tries to renew or release: MUST FAIL
    assert lock_provider.renew(token_stale) is False
    assert lock_provider.release(token_stale) is False

    # Active worker can successfully renew and release
    assert lock_provider.renew(token_active) is True
    assert lock_provider.release(token_active) is True


# =============================================================================
# 3. MULTI-NODE WORKER DISPATCH & LEASE RECOVERY TESTS
# =============================================================================

def test_multi_node_worker_coordinator():
    """Test distributed worker registration, heartbeats, task claims, and dead worker recovery."""
    lock_provider = InMemoryDistributedLockProvider()
    coordinator = DistributedWorkerCoordinator(lock_provider)

    node_1 = coordinator.register_node(node_id="worker-node-1", hostname="host-a")
    node_2 = coordinator.register_node(node_id="worker-node-2", hostname="host-b")

    assert node_1.status == NodeStatus.ACTIVE
    assert node_2.status == NodeStatus.ACTIVE
    assert len(coordinator.list_nodes()) == 2

    # Node 1 claims task
    token = coordinator.claim_task("task-100", "worker-node-1", ttl_seconds=0.05, tenant_id="tenant-x")
    assert token is not None
    assert token.owner == "worker-node-1"

    # Node 2 cannot claim same task concurrently
    token_dup = coordinator.claim_task("task-100", "worker-node-2", ttl_seconds=10.0, tenant_id="tenant-x")
    assert token_dup is None

    # Simulate node 1 death (heartbeat timeout)
    time.sleep(0.06)
    dead_nodes = coordinator.detect_dead_nodes(timeout_seconds=0.01)
    assert "worker-node-1" in dead_nodes
    assert coordinator.get_node("worker-node-1").status == NodeStatus.DEAD

    # Node 2 recovers the task after node 1 death
    recovered_token = coordinator.recover_task_lease("task-100", "worker-node-2", ttl_seconds=10.0, tenant_id="tenant-x")
    assert recovered_token is not None
    assert recovered_token.owner == "worker-node-2"
    assert recovered_token.fencing_token > token.fencing_token


# =============================================================================
# 4. ADVERSARIAL MULTI-TENANT BOUNDARY ISOLATION TESTS
# =============================================================================

def test_tenant_isolation_events_and_investigations(clean_bundle):
    """Ensure events, investigations, and decisions strictly isolate across tenants."""
    now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    # Tenant A event & candidate
    event_a = EnterpriseEvent(
        event_id="evt-tenant-a-1",
        source="github",
        source_event_id="gh-1",
        event_type=EnterpriseEventType.CODE_PUSHED,
        timestamp=now_iso,
        repository="enterprise/core-service",
        commit="commit-aaa",
        release_id="rel-alpha",
        tenant_id="tenant-a",
    )
    clean_bundle.events.append_event(event_a)

    # Tenant B event & candidate with SAME commit & release ID (namespace collision test)
    event_b = EnterpriseEvent(
        event_id="evt-tenant-b-1",
        source="github",
        source_event_id="gh-2",
        event_type=EnterpriseEventType.CODE_PUSHED,
        timestamp=now_iso,
        repository="enterprise/core-service",
        commit="commit-aaa",
        release_id="rel-alpha",
        tenant_id="tenant-b",
    )
    clean_bundle.events.append_event(event_b)

    # 1. Tenant A query cannot see Tenant B events
    events_tenant_a = clean_bundle.events.list_events(tenant_id="tenant-a")
    assert len(events_tenant_a) == 1
    assert events_tenant_a[0].event_id == "evt-tenant-a-1"

    events_tenant_b = clean_bundle.events.list_events(tenant_id="tenant-b")
    assert len(events_tenant_b) == 1
    assert events_tenant_b[0].event_id == "evt-tenant-b-1"

    # 2. Cross-tenant event fetch returns None
    assert clean_bundle.events.get_event("evt-tenant-a-1", tenant_id="tenant-b") is None
    assert clean_bundle.events.get_event("evt-tenant-b-1", tenant_id="tenant-a") is None

    # 3. Decision isolation
    dec_a = ReleaseDecision(
        release_id="rel-alpha",
        outcome=ReleaseDecisionOutcome.READY,
        risk_level=RiskLevel.LOW,
        confidence=1.0,
        rationale="Tenant A approved",
        tenant_id="tenant-a",
    )
    dec_b = ReleaseDecision(
        release_id="rel-alpha",
        outcome=ReleaseDecisionOutcome.BLOCKED,
        risk_level=RiskLevel.HIGH,
        confidence=0.9,
        rationale="Tenant B blocked",
        tenant_id="tenant-b",
    )
    clean_bundle.decisions.save_decision(dec_a)
    clean_bundle.decisions.save_decision(dec_b)

    assert clean_bundle.decisions.get_latest_decision("rel-alpha", tenant_id="tenant-a").outcome == ReleaseDecisionOutcome.READY
    assert clean_bundle.decisions.get_latest_decision("rel-alpha", tenant_id="tenant-b").outcome == ReleaseDecisionOutcome.BLOCKED


def test_tenant_aware_entity_resolution(clean_bundle):
    """Verify deterministic entity resolution rejects cross-tenant release candidate matching."""
    resolver = DeterministicEntityResolver(clean_bundle)

    # Register candidate under Tenant 1
    cand_1 = ReleaseCandidate(
        release_id="rel-payment-101",
        service_name="payment-service",
        version="v1.0.1",
        repository="enterprise/payment-service",
        commit="hash-c0ffee",
        tenant_id="tenant-1",
    )
    clean_bundle.entities.save_candidate(cand_1)

    # Event with matching commit hash under Tenant 2
    event_tenant_2 = EnterpriseEvent(
        event_id="evt-external-200",
        source="github",
        source_event_id="evt-200",
        event_type=EnterpriseEventType.CODE_PUSHED,
        timestamp="2026-09-09T12:00:00Z",
        repository="enterprise/payment-service",
        commit="hash-c0ffee",
        tenant_id="tenant-2",
    )

    # Resolver must NOT resolve candidate from Tenant 1
    matches = resolver.resolve_affected_releases(event_tenant_2)
    assert len(matches) == 0, "Cross-tenant entity resolution violation!"

    # Event under Tenant 1 resolves candidate successfully
    event_tenant_1 = EnterpriseEvent(
        event_id="evt-external-100",
        source="github",
        source_event_id="evt-100",
        event_type=EnterpriseEventType.CODE_PUSHED,
        timestamp="2026-09-09T12:00:00Z",
        repository="enterprise/payment-service",
        commit="hash-c0ffee",
        tenant_id="tenant-1",
    )
    matches_1 = resolver.resolve_affected_releases(event_tenant_1)
    assert len(matches_1) == 1
    assert matches_1[0].release_id == "rel-payment-101"


def test_tenant_isolation_graph(clean_bundle):
    """Verify EvidenceGraph snapshots are strictly scoped to the requesting tenant."""
    # Tenant 1 node and edge
    clean_bundle.graph.save_node("node-1", "RELEASE", {"service": "svc-1"}, valid_from="2026-09-09T10:00:00Z", tenant_id="tenant-1")
    clean_bundle.graph.save_node("node-2", "EVIDENCE", {"hash": "abc"}, valid_from="2026-09-09T10:00:00Z", tenant_id="tenant-1")
    clean_bundle.graph.save_edge("node-1", "node-2", "VERIFIED_BY", {}, valid_from="2026-09-09T10:00:00Z", tenant_id="tenant-1")

    # Tenant 2 node
    clean_bundle.graph.save_node("node-3", "RELEASE", {"service": "svc-2"}, valid_from="2026-09-09T10:00:00Z", tenant_id="tenant-2")

    # Snapshot for Tenant 1 has only node-1 and node-2
    g1 = clean_bundle.graph.get_graph_snapshot(tenant_id="tenant-1")
    assert len(g1.nodes) == 2
    assert "node-1" in g1.nodes
    assert "node-2" in g1.nodes
    assert "node-3" not in g1.nodes

    # Snapshot for Tenant 2 has only node-3
    g2 = clean_bundle.graph.get_graph_snapshot(tenant_id="tenant-2")
    assert len(g2.nodes) == 1
    assert "node-3" in g2.nodes
    assert "node-1" not in g2.nodes


# =============================================================================
# 5. HARDENED PUBLIC INGRESS & HEALTH / PROMETHEUS METRICS TESTS
# =============================================================================

def test_ingress_health_and_readiness_endpoints(clean_bundle):
    """Test separated /health/live, /health/ready, /health/dependencies, and /metrics."""
    app = create_ingress_app(clean_bundle)
    client = TestClient(app)

    # 1. Liveness
    resp_live = client.get("/health/live")
    assert resp_live.status_code == 200
    assert resp_live.json()["status"] == "ALIVE"

    # 2. Readiness
    resp_ready = client.get("/health/ready")
    assert resp_ready.status_code == 200
    assert resp_ready.json()["status"] == "READY"
    assert resp_ready.json()["database"] == "READY"

    # 3. Dependencies
    resp_deps = client.get("/health/dependencies")
    assert resp_deps.status_code == 200
    deps = resp_deps.json()["dependencies"]
    assert deps["database"]["status"] == "UP"
    assert deps["workers"]["status"] == "UP"

    # 4. Prometheus plaintext metrics
    resp_metrics = client.get("/metrics")
    assert resp_metrics.status_code == 200
    assert "text/plain" in resp_metrics.headers["content-type"]
    body = resp_metrics.text
    assert "# HELP oracle_events_received_total" in body
    assert "# TYPE oracle_events_received_total counter"


def test_ingress_payload_limit_and_hmac_enforcement(clean_bundle):
    """Test request payload size enforcement (5MB limit) and HMAC verification."""
    secret = "production-ingress-secret"
    app = create_ingress_app(clean_bundle, webhook_secret=secret)
    client = TestClient(app)

    # 1. Reject oversized payload (> 5MB)
    oversized = b"x" * (5 * 1024 * 1024 + 10)
    resp_large = client.post("/api/v1/events/github", content=oversized)
    assert resp_large.status_code == 413

    # 2. Reject invalid HMAC signature
    normal_payload = json.dumps({"action": "push", "repository": {"name": "test"}}).encode("utf-8")
    resp_unauth = client.post(
        "/api/v1/events/github",
        content=normal_payload,
        headers={"x-hub-signature-256": "sha256=invalid-signature"},
    )
    assert resp_unauth.status_code == 401

    # 3. Accept valid HMAC signature
    valid_sig = "sha256=" + hmac.new(secret.encode("utf-8"), normal_payload, hashlib.sha256).hexdigest()
    resp_valid = client.post(
        "/api/v1/events/github",
        content=normal_payload,
        headers={
            "x-hub-signature-256": valid_sig,
            "x-timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "x-tenant-id": "tenant-corp",
        },
    )
    assert resp_valid.status_code == 202
    assert resp_valid.json()["status"] == "ACCEPTED"
    assert resp_valid.json()["tenant_id"] == "tenant-corp"


def test_ingress_webhook_registration_api(clean_bundle):
    """Test webhook registration management endpoints."""
    app = create_ingress_app(clean_bundle)
    client = TestClient(app)

    # Register webhook
    payload = {
        "provider": "mock",
        "target_entity": "enterprise/checkout",
        "callback_url": "https://oracle.corp.com/api/v1/events/mock",
        "event_types": ["push", "pull_request"],
    }
    resp = client.post("/api/v1/webhooks/registrations", json=payload, headers={"x-tenant-id": "tenant-alpha"})
    assert resp.status_code == 200
    data = resp.json()
    reg_id = data.get("registration_id") or data.get("registration", {}).get("registration_id")
    assert reg_id is not None

    # List registrations
    list_resp = client.get("/api/v1/webhooks/registrations", headers={"x-tenant-id": "tenant-alpha"})
    assert list_resp.status_code == 200
    assert len(list_resp.json()["registrations"]) == 1

    # Delete registration
    del_resp = client.delete(f"/api/v1/webhooks/registrations/{reg_id}", headers={"x-tenant-id": "tenant-alpha"})
    assert del_resp.status_code == 200


# =============================================================================
# 6. OPERATOR CLI & CONTROLLED REPLAY TESTS
# =============================================================================

def test_operator_cli_inspection_commands(clean_bundle, capsys):
    """Test operator CLI inspect commands: status, health, events, workers, drift."""
    cli = OracleCLI(clean_bundle)

    # 1. Status command
    ret = cli.run(["status", "--json", "--tenant-id", "default"])
    assert ret == 0
    captured = capsys.readouterr()
    status_data = json.loads(captured.out)
    assert status_data["status"] == "OPERATIONAL"
    assert status_data["version"] == "4.5.0"

    # 2. Health command
    ret = cli.run(["health", "--json"])
    assert ret == 0
    captured = capsys.readouterr()
    health_data = json.loads(captured.out)
    assert health_data["liveness"] == "ALIVE"
    assert health_data["readiness"] == "READY"

    # 3. Workers command
    ret = cli.run(["workers", "--json"])
    assert ret == 0
    captured = capsys.readouterr()
    workers_data = json.loads(captured.out)
    assert workers_data["status"] == "ACTIVE"

    # 4. Drift command
    ret = cli.run(["drift", "--json"])
    assert ret == 0
    captured = capsys.readouterr()
    drift_data = json.loads(captured.out)
    assert "expired_evidence_count" in drift_data


def test_operator_cli_controlled_replay(clean_bundle, capsys):
    """Test controlled replay with authorization, dry-run, and side-effect suppression."""
    now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    event = EnterpriseEvent(
        event_id="evt-replay-test-1",
        source="github",
        source_event_id="src-99",
        event_type=EnterpriseEventType.CODE_PUSHED,
        timestamp=now_iso,
        release_id="rel-replay-100",
        tenant_id="tenant-audit",
    )
    clean_bundle.events.append_event(event)

    # CLI with admin token protection
    cli = OracleCLI(clean_bundle, admin_token="super-secret-admin")

    # Unauthorized replay fails
    ret_unauth = cli.run(["replay", "--event", "evt-replay-test-1", "--tenant-id", "tenant-audit", "--json"])
    assert ret_unauth == 2
    captured = capsys.readouterr()
    assert "authorization token missing or invalid" in captured.out

    # Authorized dry-run replay succeeds
    ret_auth = cli.run([
        "replay",
        "--event", "evt-replay-test-1",
        "--dry-run",
        "--auth-token", "super-secret-admin",
        "--tenant-id", "tenant-audit",
        "--json",
    ])
    assert ret_auth == 0
    captured = capsys.readouterr()
    replay_data = json.loads(captured.out)
    assert replay_data["status"] == "REPLAY_COMPLETED"
    assert replay_data["dry_run"] is True
    assert replay_data["events_replayed"] == 1
    assert replay_data["suppressed_side_effects"] == 1

    # Audit journal contains record of the replay
    audits = clean_bundle.audit.query_audit(action="CONTROLLED_REPLAY")
    assert len(audits) >= 1
    assert audits[0]["entity_id"] == "evt-replay-test-1"


# =============================================================================
# 7. PROVIDER VERIFICATION HARNESS & CAPABILITY MATRIX
# =============================================================================

def test_provider_verification_harness():
    """Verify ProviderVerificationHarness classification across all required providers."""
    harness = ProviderVerificationHarness()
    results = harness.run_all_verifications(mode=PilotExecutionMode.MOCK)

    assert "github" in results
    assert "jira" in results
    assert "ci" in results
    assert "security" in results

    # Under MOCK mode, classification must reflect MOCK VERIFIED (not LIVE VERIFIED)
    for prov_name, rep in results.items():
        assert rep.overall_capability == CapabilityStatus.MOCK_VERIFIED
        assert rep.dimensions["connectivity"] in [CapabilityStatus.MOCK_VERIFIED, CapabilityStatus.IMPLEMENTED]
        assert rep.dimensions["schema"] == CapabilityStatus.REAL_IMPLEMENTATION
        assert rep.dimensions["idempotency"] == CapabilityStatus.REAL_IMPLEMENTATION

    # Generate formal report
    report_text = harness.generate_report(results)
    assert "PROVIDER CONNECTIVITY & CAPABILITY CLASSIFICATION MATRIX" in report_text
    assert "MOCK VERIFIED" in report_text
    assert "LIVE VERIFIED" not in report_text or "0 /" in report_text
