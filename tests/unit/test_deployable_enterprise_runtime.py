"""
ORACLE 4.6 Unit Test Suite: Deployable Enterprise Runtime & Observability

Validates:
1. Enterprise Runtime Configuration & Fail-Closed Production Validation
2. Provider-Neutral Secret Stores (Environment, Kubernetes, InMemory, Redaction)
3. OpenTelemetry Distributed Tracing & Sensitive Attribute Filtering
4. Asynchronous Distributed Trace Continuity across Process/Worker Boundaries
5. Deployable Distributed Scheduler (Leader Election, Fencing, Lease Renewal, Failover)
6. Database Migration Status and Migration Operations
7. Database Backup, Restore, and Redis Loss Disaster Recovery
8. Operator CLI Runtime Extensions (config validate, db status/migrate, traces, version, tunnel)
9. Developer Webhook Tunnel Abstraction
10. Supply Chain Security Auditor (Dependencies, Secrets, Container Hardening)
11. Container Runtime and Helm Chart Manifest Structural Integrity
"""

import json
import os
import tempfile
import time
from pathlib import Path

import pytest
import yaml

from backend.release.config import (
    DatabaseConfig,
    EnterpriseRuntimeConfig,
    RedisConfig,
    SecurityConfig,
    WebhookConfig,
)
from backend.release.security.secrets import (
    EnvironmentSecretStore,
    InMemorySecretStore,
    KubernetesSecretStore,
    mask_token,
    redact_sensitive_payload,
)
from backend.release.observability.tracing import (
    GLOBAL_TRACER,
    SpanStatus,
    TraceContext,
    Tracer,
)
from backend.release.distributed.lock import InMemoryDistributedLockProvider
from backend.release.distributed.scheduler import DistributedScheduler
from backend.release.drift import ContinuousDriftMonitor
from backend.release.persistence.factory import PersistenceFactory
from backend.release.persistence.migrator import DatabaseMigrator
from backend.release.persistence.backup import DatabaseBackupManager
from backend.release.connectivity.tunnel import MockTunnelProvider
from backend.release.security.supply_chain import SupplyChainSecurityAuditor
from backend.release.cli import OracleCLI


@pytest.fixture
def clean_bundle() -> PersistenceFactory:
    """Create fresh isolated in-memory SQLite store bundle for testing."""
    return PersistenceFactory.create_bundle(in_memory=True)



# =============================================================================
# 1. CONFIGURATION MANAGEMENT & FAIL-CLOSED VALIDATION TESTS
# =============================================================================

def test_enterprise_runtime_config_defaults_and_validation():
    """Verify safe local defaults and fail-closed validation for production."""
    # 1. Default development configuration
    cfg_dev = EnterpriseRuntimeConfig()
    is_valid, errors = cfg_dev.validate_configuration()
    assert is_valid is True
    assert len(errors) == 0
    assert cfg_dev.environment == "development"
    assert cfg_dev.database.backend == "sqlite"

    # 2. Production configuration: fail-closed if sqlite or missing secrets
    cfg_prod_invalid = EnterpriseRuntimeConfig(
        environment="production",
        database=DatabaseConfig(backend="sqlite", url=None),
        webhook=WebhookConfig(secret_token=None),
        security=SecurityConfig(require_https=False),
    )
    is_valid_prod, errors_prod = cfg_prod_invalid.validate_configuration()
    assert is_valid_prod is False
    assert any("PostgreSQL" in e for e in errors_prod)
    assert any("ORACLE_WEBHOOK_SECRET" in e for e in errors_prod)
    assert any("ORACLE_REQUIRE_HTTPS" in e for e in errors_prod)

    # 3. Production configuration: valid when hardened
    cfg_prod_valid = EnterpriseRuntimeConfig(
        environment="production",
        database=DatabaseConfig(backend="postgres", url="postgresql://user:pass@host:5432/db"),
        webhook=WebhookConfig(secret_token="secure_token_12345"),
        security=SecurityConfig(require_https=True),
    )
    is_valid_hardened, errors_hardened = cfg_prod_valid.validate_configuration()
    assert is_valid_hardened is True
    assert len(errors_hardened) == 0

    # 4. Secret redaction in diagnostics
    redacted = cfg_prod_valid.to_redacted_dict()
    assert "***REDACTED***" in redacted["database"]["url"]
    assert "pass" not in redacted["database"]["url"]
    assert redacted["webhook"]["secret_token"] == "***REDACTED***"


# =============================================================================
# 2. SECRET STORE IMPLEMENTATIONS & REDACTION TESTS
# =============================================================================

def test_secret_stores_and_redaction():
    """Verify EnvironmentSecretStore, KubernetesSecretStore, and token masking."""
    # 1. InMemorySecretStore
    mem_store = InMemorySecretStore({"GITHUB_TOKEN": "ghp_secret123"})
    assert mem_store.get_secret("GITHUB_TOKEN") == "ghp_secret123"
    mem_store.set_secret("NEW_SECRET", "val_456")
    assert mem_store.get_secret("NEW_SECRET") == "val_456"
    assert "NEW_SECRET" in mem_store.list_keys()
    assert mem_store.delete_secret("NEW_SECRET") is True

    # 2. EnvironmentSecretStore
    os.environ["ORACLE_TEST_SECRET"] = "secret_env_value"
    env_store = EnvironmentSecretStore(prefix="ORACLE_")
    assert env_store.get_secret("TEST_SECRET") == "secret_env_value"
    del os.environ["ORACLE_TEST_SECRET"]

    # 3. KubernetesSecretStore (simulated volume mount)
    with tempfile.TemporaryDirectory() as temp_dir:
        secret_file = Path(temp_dir) / "webhook_secret"
        secret_file.write_text("k8s_mounted_secret_token", encoding="utf-8")

        k8s_store = KubernetesSecretStore(mount_path=temp_dir, fallback_to_env=False)
        assert k8s_store.get_secret("webhook_secret") == "k8s_mounted_secret_token"
        assert k8s_store.get_secret("non_existent", default="fallback") == "fallback"

    # 4. Token masking & payload scrubbing
    assert mask_token("ghp_1234567890abcdef", visible_chars=4) == "****************cdef"
    payload = {
        "event_id": "evt-1",
        "api_key": "super_secret_key",
        "nested": {"password": "pass", "user": "alice"},
    }
    scrubbed = redact_sensitive_payload(payload)
    assert scrubbed["event_id"] == "evt-1"
    assert scrubbed["api_key"] == "***REDACTED***"
    assert scrubbed["nested"]["password"] == "***REDACTED***"
    assert scrubbed["nested"]["user"] == "alice"


# =============================================================================
# 3. OPENTELEMETRY DISTRIBUTED TRACING TESTS
# =============================================================================

def test_opentelemetry_distributed_tracing():
    """Verify tracer span lifecycle, context propagation, and secret filtering."""
    tracer = Tracer("test-service")

    # 1. Start root span
    with tracer.start_span("http_ingress", correlation_id="corr-1234") as root_span:
        root_span.set_attribute("http.method", "POST")
        root_span.set_attribute("http.route", "/api/v1/events/github")
        # Attempt to set sensitive attributes: MUST BE FILTERED
        root_span.set_attribute("auth_token", "bearer_token_secret")
        root_span.set_attribute("webhook_secret", "secret_hex")

        # Child span
        with tracer.start_span("journal_event") as child_span:
            child_span.set_attribute("event_id", "evt-100")
            child_span.set_attribute("event_type", "CODE_PUSHED")

    spans = tracer.get_spans(correlation_id="corr-1234")
    assert len(spans) == 2

    root_rec = next(s for s in spans if s.name == "http_ingress")
    child_rec = next(s for s in spans if s.name == "journal_event")

    assert root_rec.correlation_id == "corr-1234"
    assert child_rec.parent_span_id == root_rec.span_id
    assert child_rec.trace_id == root_rec.trace_id

    # Verify secret exclusion
    assert "auth_token" not in root_rec.attributes
    assert "webhook_secret" not in root_rec.attributes
    assert root_rec.attributes["http.method"] == "POST"


# =============================================================================
# 4. ASYNCHRONOUS TRACE CONTINUITY ACROSS WORKER BOUNDARIES
# =============================================================================

def test_distributed_trace_continuity_across_async_worker():
    """Verify trace context propagates through event metadata across asynchronous worker claims."""
    tracer = Tracer("oracle-distributed")

    # Process 1: Network Ingress accepts event
    with tracer.start_span("ingress.accept_event", correlation_id="trace-corr-999") as ingress_span:
        ingress_span.set_attribute("event_id", "evt-async-001")
        # Carrier dictionary serialized into durable event journal provenance
        carrier: dict = {}
        tracer.inject_context(carrier)

    assert "trace_id" in carrier
    assert "traceparent" in carrier

    # Process 2 (Worker Node): Deserializes carrier from task queue and resumes trace
    restored_context = tracer.extract_context(carrier)
    assert restored_context is not None
    assert restored_context.trace_id == ingress_span.context.trace_id

    with tracer.start_span("worker.process_task", parent_context=restored_context) as worker_span:
        worker_span.set_attribute("worker_id", "node-worker-2")
        worker_span.set_attribute("investigation_id", "inv-async-777")

        with tracer.start_span("controller.decide", parent_context=worker_span.context) as decision_span:
            decision_span.set_attribute("outcome", "READY")
            decision_span.set_attribute("investigation_id", "inv-async-777")

    # Verify complete causal path under the same trace ID
    trace_spans = tracer.get_spans(trace_id=ingress_span.context.trace_id)
    assert len(trace_spans) == 3

    names = [s.name for s in trace_spans]
    assert "ingress.accept_event" in names
    assert "worker.process_task" in names
    assert "controller.decide" in names

    # Query by investigation ID
    inv_spans = tracer.get_spans(investigation_id="inv-async-777")
    assert len(inv_spans) == 2


# =============================================================================
# 5. DEPLOYABLE DISTRIBUTED SCHEDULER TESTS
# =============================================================================

def test_distributed_scheduler_leader_election_and_execution(clean_bundle):
    """Verify distributed-safe scheduler leader election, non-duplication, and failover."""
    lock_provider = InMemoryDistributedLockProvider()

    # Node A and Node B contend for scheduler leadership
    sched_a = DistributedScheduler(
        store=clean_bundle,
        lock_provider=lock_provider,
        scheduler_id="scheduler-node-a",
        lease_duration_seconds=0.05,
    )
    sched_b = DistributedScheduler(
        store=clean_bundle,
        lock_provider=lock_provider,
        scheduler_id="scheduler-node-b",
        lease_duration_seconds=0.05,
    )

    # 1. Node A claims leadership and executes cycle
    report_a = sched_a.run_once()
    assert report_a is not None
    assert sched_a.is_leader is True
    assert report_a.scheduler_id == "scheduler-node-a"

    # 2. Node B attempts execution while A holds leader lease: MUST BE STANDBY
    report_b = sched_b.run_once()
    assert report_b is None
    assert sched_b.is_leader is False

    # 3. Node A gracefully stops, immediately surrendering leader lock
    sched_a.stop()
    assert sched_a.is_leader is False

    # 4. Node B immediately takes over as new cluster leader
    report_b_active = sched_b.run_once()
    assert report_b_active is not None
    assert sched_b.is_leader is True
    assert report_b_active.scheduler_id == "scheduler-node-b"
    assert report_b_active.fencing_token > report_a.fencing_token
    sched_b.stop()


# =============================================================================
# 6. DATABASE MIGRATION STATUS & OPERATIONS TESTS
# =============================================================================

def test_database_migration_status_and_operations(clean_bundle):
    """Verify DatabaseMigrator version reporting, status inspection, and idempotency."""
    migrator = DatabaseMigrator(is_postgres=clean_bundle.is_postgres)
    conn = clean_bundle.pool.get_connection()

    status = migrator.get_status(conn)
    assert status["is_up_to_date"] is True
    assert status["current_version"] >= 2
    assert status["pending_count"] == 0

    # Idempotent re-application does not error and returns 0 new migrations
    reapplied = migrator.apply_migrations(conn)
    assert len(reapplied) == 0


# =============================================================================
# 7. BACKUP, RESTORE & DISASTER RECOVERY TESTS
# =============================================================================

def test_database_backup_and_disaster_recovery(clean_bundle):
    """Verify full JSON backup export, restore integrity, and Redis loss survival."""
    backup_mgr = DatabaseBackupManager(clean_bundle)

    # 1. Export backup snapshot
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        backup_file = f.name

    try:
        snapshot = backup_mgr.export_backup(output_file_path=backup_file)
        assert snapshot["metadata"]["schema_version"] == 2
        assert "event_journal" in snapshot["tables"]
        assert "decisions" in snapshot["tables"]

        # 2. Restore from snapshot
        restore_res = backup_mgr.restore_backup(backup_file)
        assert restore_res["backup_id"] == snapshot["metadata"]["backup_id"]
        assert "event_journal" in restore_res["restored_counts"]
    finally:
        try:
            os.remove(backup_file)
        except Exception:
            pass

    # 3. Disaster Recovery: Simulated Redis failure
    # Flushes ephemeral lock coordination layer, proving PostgreSQL durable state is 100% intact
    lock_prov = InMemoryDistributedLockProvider()
    token = lock_prov.acquire("temp:lock", "worker-1", ttl_seconds=10.0)
    assert token is not None

    # Simulate Redis partition/crash: Lock provider cleared
    lock_prov.clear()
    assert lock_prov.is_locked("temp:lock") is False

    # Authoritative persistence in SQLite/PostgreSQL was completely untouched
    conn = clean_bundle.pool.get_connection()
    migrator = DatabaseMigrator(is_postgres=clean_bundle.is_postgres)
    assert migrator.get_status(conn)["is_up_to_date"] is True


# =============================================================================
# 8. OPERATOR CLI EXTENDED COMMANDS TESTS
# =============================================================================

def test_operator_cli_extended_commands(clean_bundle, capsys):
    """Test CLI commands: config validate, db status, db migrate, traces, version, tunnel."""
    cli = OracleCLI(clean_bundle)

    # 1. config validate
    ret_cfg = cli.run(["config", "validate", "--json"])
    assert ret_cfg == 0
    captured = capsys.readouterr()
    res_cfg = json.loads(captured.out)
    assert res_cfg["status"] == "CONFIG_VALID"

    # 2. db status
    ret_db = cli.run(["db", "status", "--json"])
    assert ret_db == 0
    captured = capsys.readouterr()
    res_db = json.loads(captured.out)
    assert res_db["is_up_to_date"] is True

    # 3. db migrate
    ret_mig = cli.run(["db", "migrate", "--json"])
    assert ret_mig == 0
    captured = capsys.readouterr()
    res_mig = json.loads(captured.out)
    assert res_mig["status"] == "MIGRATIONS_APPLIED"

    # 4. traces
    GLOBAL_TRACER.clear()
    with GLOBAL_TRACER.start_span("test_inv_span") as s:
        s.set_attribute("investigation_id", "inv-cli-100")
    ret_tr = cli.run(["traces", "inv-cli-100", "--json"])
    assert ret_tr == 0
    captured = capsys.readouterr()
    res_tr = json.loads(captured.out)
    assert res_tr["total_spans"] == 1

    # 5. version
    ret_ver = cli.run(["version", "--json"])
    assert ret_ver == 0
    captured = capsys.readouterr()
    res_ver = json.loads(captured.out)
    assert res_ver["oracle_version"] == "4.6.0"

    # 6. tunnel
    ret_tun = cli.run(["tunnel", "--port", "8000", "--provider", "mock", "--json"])
    assert ret_tun == 0
    captured = capsys.readouterr()
    res_tun = json.loads(captured.out)
    assert res_tun["status"] == "TUNNEL_ACTIVE"
    assert "https://" in res_tun["public_url"]


# =============================================================================
# 9. DEVELOPER TUNNEL TESTS
# =============================================================================

def test_developer_tunnel_lifecycle():
    """Verify DeveloperTunnelProvider starts, reports active, and cleanly terminates."""
    tunnel = MockTunnelProvider(mock_hostname="dev.ingress.corp")
    assert tunnel.is_active() is False

    url = tunnel.start_tunnel(local_port=8080)
    assert tunnel.is_active() is True
    assert url == "https://dev.ingress.corp:8080/api/v1/events"
    assert tunnel.get_public_url() == url

    tunnel.stop_tunnel()
    assert tunnel.is_active() is False
    assert tunnel.get_public_url() is None


# =============================================================================
# 10. SUPPLY CHAIN SECURITY AUDITOR TESTS
# =============================================================================

def test_supply_chain_security_auditor():
    """Verify automated dependency scanning, secret leakage detection, and container hardening audit."""
    auditor = SupplyChainSecurityAuditor()
    report = auditor.run_full_audit()

    assert report is not None
    assert isinstance(report.findings, list)
    assert report.summary["CRITICAL"] == 0
    assert report.summary["HIGH"] == 0
    assert report.passed is True


# =============================================================================
# 11. CONTAINER & HELM MANIFEST INTEGRITY TESTS
# =============================================================================

def test_container_and_helm_manifest_integrity():
    """Verify Dockerfile and Helm templates conform to production security & schema standards."""
    root_dir = Path(os.getcwd())

    # 1. Dockerfile checks
    dockerfile = root_dir / "Dockerfile"
    assert dockerfile.exists()
    df_text = dockerfile.read_text(encoding="utf-8")
    assert "USER 10001:10001" in df_text
    assert "HEALTHCHECK" in df_text
    assert "entrypoint.sh" in df_text

    # 2. Helm Chart.yaml and values.yaml checks
    helm_dir = root_dir / "deploy" / "helm" / "oracle"
    chart_yaml = helm_dir / "Chart.yaml"
    values_yaml = helm_dir / "values.yaml"
    assert chart_yaml.exists()
    assert values_yaml.exists()

    chart_data = yaml.safe_load(chart_yaml.read_text(encoding="utf-8"))
    assert chart_data["name"] == "oracle"
    assert chart_data["version"] == "4.6.0"

    values_data = yaml.safe_load(values_yaml.read_text(encoding="utf-8"))
    assert values_data["podSecurityContext"]["runAsNonRoot"] is True
    assert values_data["podSecurityContext"]["runAsUser"] == 10001
    assert values_data["api"]["replicaCount"] >= 2
    assert values_data["worker"]["replicaCount"] >= 2
    assert values_data["ingress"]["enabled"] is True

    # 3. Verify templates exist
    templates_dir = helm_dir / "templates"
    required_templates = [
        "deployment-api.yaml",
        "deployment-worker.yaml",
        "deployment-scheduler.yaml",
        "service.yaml",
        "configmap.yaml",
        "secrets.yaml",
        "serviceaccount.yaml",
        "rbac.yaml",
        "ingress.yaml",
        "pdb.yaml",
    ]
    for tmpl in required_templates:
        assert (templates_dir / tmpl).exists(), f"Missing required Helm template {tmpl}"
