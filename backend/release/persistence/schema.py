"""
Database Schema DDL & Migration Definitions for ORACLE (Brick 4.4)

Provides dialect-agnostic and dialect-specific DDL for SQLite and PostgreSQL.
Includes indexes, foreign keys, unique constraints, and schema versions.
"""

from __future__ import annotations

from typing import List, Tuple

# -----------------------------------------------------------------------------
# SQLITE DDL STATEMENTS
# -----------------------------------------------------------------------------

SQLITE_SCHEMA_V1 = [
    # 1. Event Journal (Append-only)
    """
    CREATE TABLE IF NOT EXISTS event_journal (
        event_id TEXT PRIMARY KEY,
        source TEXT NOT NULL,
        source_event_id TEXT NOT NULL,
        event_type TEXT NOT NULL,
        timestamp TEXT NOT NULL,
        received_at TEXT NOT NULL,
        entity_type TEXT NOT NULL,
        entity_id TEXT NOT NULL,
        repository TEXT NOT NULL,
        commit_hash TEXT NOT NULL,
        release_id TEXT NOT NULL,
        work_item_id TEXT NOT NULL,
        service_id TEXT NOT NULL,
        environment TEXT NOT NULL,
        correlation_keys_json TEXT NOT NULL DEFAULT '{}',
        payload_json TEXT NOT NULL DEFAULT '{}',
        provenance_json TEXT NOT NULL DEFAULT '{}',
        processing_status TEXT NOT NULL DEFAULT 'PENDING',
        attempt_count INTEGER NOT NULL DEFAULT 0,
        correlation_id TEXT NOT NULL DEFAULT ''
    );
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_event_release ON event_journal(release_id);
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_event_type ON event_journal(event_type);
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_event_commit ON event_journal(commit_hash);
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_event_received ON event_journal(received_at);
    """,

    # 2. Event Idempotency (Atomic Uniqueness)
    """
    CREATE TABLE IF NOT EXISTS event_idempotency (
        idempotency_key TEXT PRIMARY KEY,
        event_id TEXT NOT NULL,
        source TEXT NOT NULL,
        source_event_id TEXT NOT NULL,
        event_type TEXT NOT NULL,
        registered_at TEXT NOT NULL,
        ttl_seconds INTEGER DEFAULT NULL,
        CONSTRAINT uq_event_identity UNIQUE (source, source_event_id, event_type)
    );
    """,

    # 3. Investigations
    """
    CREATE TABLE IF NOT EXISTS investigations (
        investigation_id TEXT PRIMARY KEY,
        release_id TEXT NOT NULL,
        service_name TEXT NOT NULL,
        version TEXT NOT NULL,
        commit_hash TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'PENDING',
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        candidate_json TEXT NOT NULL,
        outages_json TEXT NOT NULL DEFAULT '[]',
        telemetry_json TEXT NOT NULL DEFAULT '{}'
    );
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_inv_release ON investigations(release_id);
    """,

    # 4. Investigation Gaps
    """
    CREATE TABLE IF NOT EXISTS investigation_gaps (
        investigation_id TEXT NOT NULL,
        gap_id TEXT NOT NULL,
        gap_type TEXT NOT NULL,
        target_entity TEXT NOT NULL,
        description TEXT NOT NULL,
        why_needed TEXT NOT NULL,
        required_information TEXT NOT NULL,
        is_blocking INTEGER NOT NULL DEFAULT 1,
        status TEXT NOT NULL DEFAULT 'OPEN',
        resolution TEXT NOT NULL DEFAULT '',
        resolution_evidence_ids_json TEXT NOT NULL DEFAULT '[]',
        updated_at TEXT NOT NULL,
        PRIMARY KEY (investigation_id, gap_id),
        FOREIGN KEY (investigation_id) REFERENCES investigations(investigation_id) ON DELETE CASCADE
    );
    """,

    # 5. Evidence Store
    """
    CREATE TABLE IF NOT EXISTS evidence_store (
        evidence_id TEXT PRIMARY KEY,
        investigation_id TEXT DEFAULT NULL,
        source TEXT NOT NULL,
        source_type TEXT NOT NULL,
        content_hash TEXT NOT NULL,
        canonical_uri TEXT NOT NULL,
        entity_type TEXT NOT NULL,
        entity_id TEXT NOT NULL,
        commit_hash TEXT NOT NULL,
        version TEXT NOT NULL,
        valid_from TEXT NOT NULL,
        valid_until TEXT DEFAULT NULL,
        state TEXT NOT NULL DEFAULT 'VALID',
        metadata_json TEXT NOT NULL DEFAULT '{}',
        created_at TEXT NOT NULL
    );
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_evidence_inv ON evidence_store(investigation_id);
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_evidence_validity ON evidence_store(valid_until, state);
    """,

    # 6. Evidence Lifecycle Transitions
    """
    CREATE TABLE IF NOT EXISTS evidence_lifecycle (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        evidence_id TEXT NOT NULL,
        state TEXT NOT NULL,
        transition_timestamp TEXT NOT NULL,
        reason TEXT NOT NULL,
        superseded_by TEXT DEFAULT NULL,
        causal_event_id TEXT DEFAULT NULL,
        FOREIGN KEY (evidence_id) REFERENCES evidence_store(evidence_id) ON DELETE CASCADE
    );
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_lifecycle_evidence ON evidence_lifecycle(evidence_id);
    """,

    # 7. Authoritative Decisions
    """
    CREATE TABLE IF NOT EXISTS decisions (
        decision_id TEXT PRIMARY KEY,
        investigation_id TEXT NOT NULL,
        release_id TEXT NOT NULL,
        outcome TEXT NOT NULL,
        risk_level TEXT NOT NULL,
        confidence REAL NOT NULL,
        rationale TEXT NOT NULL,
        blocking_factors_json TEXT NOT NULL DEFAULT '[]',
        verified_factors_json TEXT NOT NULL DEFAULT '[]',
        recommendations_json TEXT NOT NULL DEFAULT '[]',
        governed_actions_json TEXT NOT NULL DEFAULT '[]',
        evidence_ids_json TEXT NOT NULL DEFAULT '[]',
        contradiction_ids_json TEXT NOT NULL DEFAULT '[]',
        unresolved_gap_ids_json TEXT NOT NULL DEFAULT '[]',
        decision_timestamp TEXT NOT NULL,
        provenance_json TEXT NOT NULL DEFAULT '{}'
    );
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_decision_release ON decisions(release_id, decision_timestamp);
    """,

    # 8. Decision Lineage
    """
    CREATE TABLE IF NOT EXISTS decision_lineage (
        change_id TEXT PRIMARY KEY,
        release_id TEXT NOT NULL,
        previous_outcome TEXT NOT NULL,
        new_outcome TEXT NOT NULL,
        trigger_event_id TEXT NOT NULL,
        changed_evidence_ids_json TEXT NOT NULL DEFAULT '[]',
        explanation TEXT NOT NULL,
        timestamp TEXT NOT NULL
    );
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_lineage_release ON decision_lineage(release_id, timestamp);
    """,

    # 9. Governed Actions
    """
    CREATE TABLE IF NOT EXISTS governed_actions (
        action_id TEXT PRIMARY KEY,
        action_type TEXT NOT NULL,
        target_system TEXT NOT NULL,
        payload_json TEXT NOT NULL DEFAULT '{}',
        status TEXT NOT NULL DEFAULT 'PROPOSED',
        idempotency_key TEXT NOT NULL DEFAULT '',
        requires_human_approval INTEGER NOT NULL DEFAULT 1,
        authorized_by TEXT DEFAULT NULL,
        execution_timestamp TEXT DEFAULT NULL,
        audit_trail_json TEXT NOT NULL DEFAULT '[]',
        created_at TEXT NOT NULL
    );
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_action_idemp ON governed_actions(idempotency_key);
    """,

    # 10. Governed Action Executions (Atomic execution deduplication)
    """
    CREATE TABLE IF NOT EXISTS governed_action_executions (
        idempotency_key TEXT PRIMARY KEY,
        action_id TEXT NOT NULL,
        result_payload_json TEXT NOT NULL DEFAULT '{}',
        executed_at TEXT NOT NULL
    );
    """,

    # 11. Worker Leases (Distributed Task Claim & Heartbeat)
    """
    CREATE TABLE IF NOT EXISTS worker_leases (
        task_id TEXT PRIMARY KEY,
        task_type TEXT NOT NULL,
        payload_json TEXT NOT NULL DEFAULT '{}',
        worker_id TEXT DEFAULT NULL,
        status TEXT NOT NULL DEFAULT 'PENDING',
        attempt_count INTEGER NOT NULL DEFAULT 0,
        claimed_at TEXT DEFAULT NULL,
        lease_until TEXT DEFAULT NULL,
        heartbeat_at TEXT DEFAULT NULL,
        completed_at TEXT DEFAULT NULL,
        result_json TEXT DEFAULT NULL
    );
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_worker_queue ON worker_leases(status, lease_until);
    """,

    # 12. Evidence Graph Relational Projection (Temporal Nodes & Edges)
    """
    CREATE TABLE IF NOT EXISTS graph_nodes (
        node_id TEXT NOT NULL,
        node_type TEXT NOT NULL,
        properties_json TEXT NOT NULL DEFAULT '{}',
        valid_from TEXT NOT NULL,
        valid_until TEXT DEFAULT NULL,
        is_active INTEGER NOT NULL DEFAULT 1,
        updated_at TEXT NOT NULL,
        PRIMARY KEY (node_id, valid_from)
    );
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_nodes_temporal ON graph_nodes(valid_from, valid_until, is_active);
    """,
    """
    CREATE TABLE IF NOT EXISTS graph_edges (
        source_id TEXT NOT NULL,
        target_id TEXT NOT NULL,
        edge_type TEXT NOT NULL,
        properties_json TEXT NOT NULL DEFAULT '{}',
        valid_from TEXT NOT NULL,
        valid_until TEXT DEFAULT NULL,
        is_active INTEGER NOT NULL DEFAULT 1,
        updated_at TEXT NOT NULL,
        PRIMARY KEY (source_id, target_id, edge_type, valid_from)
    );
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_edges_temporal ON graph_edges(valid_from, valid_until, is_active);
    """,

    # 13. Registered Entity Candidates
    """
    CREATE TABLE IF NOT EXISTS entity_candidates (
        release_id TEXT PRIMARY KEY,
        service_name TEXT NOT NULL,
        version TEXT NOT NULL,
        repository TEXT NOT NULL,
        branch TEXT NOT NULL DEFAULT 'main',
        commit_hash TEXT NOT NULL,
        target_environment TEXT NOT NULL DEFAULT 'production',
        pull_request_id TEXT DEFAULT NULL,
        linked_work_items_json TEXT NOT NULL DEFAULT '[]',
        changed_components_json TEXT NOT NULL DEFAULT '[]',
        candidate_json TEXT NOT NULL,
        created_at TEXT NOT NULL
    );
    """,

    # 14. Append-Only Audit Journal
    """
    CREATE TABLE IF NOT EXISTS audit_journal (
        audit_id TEXT PRIMARY KEY,
        timestamp TEXT NOT NULL,
        actor TEXT NOT NULL,
        action TEXT NOT NULL,
        entity_type TEXT NOT NULL,
        entity_id TEXT NOT NULL,
        details_json TEXT NOT NULL DEFAULT '{}',
        correlation_id TEXT NOT NULL DEFAULT ''
    );
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_audit_entity ON audit_journal(entity_type, entity_id);
    """,

    # 15. Schema Migrations Ledger
    """
    CREATE TABLE IF NOT EXISTS schema_migrations (
        version INTEGER PRIMARY KEY,
        name TEXT NOT NULL,
        applied_at TEXT NOT NULL
    );
    """,

    # 16. Build Artifacts & Deployments (Brick 4.8)
    """
    CREATE TABLE IF NOT EXISTS build_artifacts (
        artifact_digest TEXT PRIMARY KEY,
        tenant_id TEXT NOT NULL DEFAULT 'default',
        artifact_id TEXT NOT NULL,
        artifact_name TEXT NOT NULL DEFAULT '',
        repository TEXT NOT NULL,
        commit_hash TEXT NOT NULL,
        build_id TEXT NOT NULL DEFAULT '',
        built_at TEXT NOT NULL,
        payload_json TEXT NOT NULL DEFAULT '{}'
    );
    """,
    "CREATE INDEX IF NOT EXISTS idx_art_tenant_commit ON build_artifacts(tenant_id, repository, commit_hash);",

    """
    CREATE TABLE IF NOT EXISTS deployments (
        deployment_id TEXT PRIMARY KEY,
        tenant_id TEXT NOT NULL DEFAULT 'default',
        service_id TEXT NOT NULL,
        environment TEXT NOT NULL DEFAULT 'PRODUCTION',
        artifact_digest TEXT NOT NULL,
        commit_hash TEXT NOT NULL,
        deployed_at TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'ACTIVE',
        payload_json TEXT NOT NULL DEFAULT '{}'
    );
    """,
    "CREATE INDEX IF NOT EXISTS idx_dep_tenant_service ON deployments(tenant_id, service_id, environment);",

    """
    CREATE TABLE IF NOT EXISTS runtime_services (
        service_id TEXT PRIMARY KEY,
        tenant_id TEXT NOT NULL DEFAULT 'default',
        service_name TEXT NOT NULL,
        environment TEXT NOT NULL DEFAULT 'PRODUCTION',
        exposure TEXT NOT NULL DEFAULT 'UNKNOWN',
        auth_required TEXT NOT NULL DEFAULT 'UNKNOWN',
        payload_json TEXT NOT NULL DEFAULT '{}'
    );
    """,
    "CREATE INDEX IF NOT EXISTS idx_svc_tenant_env ON runtime_services(tenant_id, environment);",

    # 17. Security Intelligence Entities (Brick 4.8)
    """
    CREATE TABLE IF NOT EXISTS security_findings (
        finding_id TEXT PRIMARY KEY,
        tenant_id TEXT NOT NULL DEFAULT 'default',
        repository TEXT NOT NULL,
        commit_hash TEXT NOT NULL,
        artifact_digest TEXT DEFAULT NULL,
        severity TEXT NOT NULL,
        category TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'ACTIVE',
        payload_json TEXT NOT NULL DEFAULT '{}'
    );
    """,
    "CREATE INDEX IF NOT EXISTS idx_sec_finding_tenant ON security_findings(tenant_id, repository, commit_hash);",
    "CREATE INDEX IF NOT EXISTS idx_sec_finding_artifact ON security_findings(artifact_digest);",

    """
    CREATE TABLE IF NOT EXISTS security_impact_assessments (
        assessment_id TEXT PRIMARY KEY,
        finding_id TEXT NOT NULL,
        tenant_id TEXT NOT NULL DEFAULT 'default',
        repository TEXT NOT NULL,
        commit_hash TEXT NOT NULL,
        artifact_digest TEXT DEFAULT NULL,
        impact_level TEXT NOT NULL,
        business_impact TEXT NOT NULL,
        payload_json TEXT NOT NULL DEFAULT '{}'
    );
    """,
    "CREATE INDEX IF NOT EXISTS idx_sec_imp_finding ON security_impact_assessments(finding_id);",

    """
    CREATE TABLE IF NOT EXISTS security_investigations (
        investigation_id TEXT PRIMARY KEY,
        tenant_id TEXT NOT NULL DEFAULT 'default',
        repository TEXT NOT NULL,
        commit_hash TEXT NOT NULL,
        artifact_digest TEXT DEFAULT NULL,
        decision_outcome TEXT NOT NULL DEFAULT 'SECURITY_UNKNOWN',
        created_at TEXT NOT NULL,
        payload_json TEXT NOT NULL DEFAULT '{}'
    );
    """,
    "CREATE INDEX IF NOT EXISTS idx_sec_inv_tenant ON security_investigations(tenant_id, repository, commit_hash);",

    """
    CREATE TABLE IF NOT EXISTS security_decisions (
        decision_id TEXT PRIMARY KEY,
        tenant_id TEXT NOT NULL DEFAULT 'default',
        repository TEXT NOT NULL,
        commit_hash TEXT NOT NULL,
        artifact_digest TEXT DEFAULT NULL,
        outcome TEXT NOT NULL,
        risk_level TEXT NOT NULL,
        created_at TEXT NOT NULL,
        payload_json TEXT NOT NULL DEFAULT '{}'
    );
    """,
    "CREATE INDEX IF NOT EXISTS idx_sec_dec_tenant ON security_decisions(tenant_id, repository, commit_hash);",

    """
    CREATE TABLE IF NOT EXISTS security_verifications (
        verification_id TEXT PRIMARY KEY,
        finding_id TEXT NOT NULL,
        tenant_id TEXT NOT NULL DEFAULT 'default',
        rescan_commit TEXT NOT NULL,
        rescan_artifact_digest TEXT DEFAULT NULL,
        status TEXT NOT NULL,
        verified_at TEXT NOT NULL,
        payload_json TEXT NOT NULL DEFAULT '{}'
    );
    """,
    "CREATE INDEX IF NOT EXISTS idx_sec_ver_finding ON security_verifications(finding_id);"
]



# -----------------------------------------------------------------------------
# POSTGRESQL DDL STATEMENTS
# -----------------------------------------------------------------------------

POSTGRES_SCHEMA_V1 = [
    """
    CREATE TABLE IF NOT EXISTS event_journal (
        event_id VARCHAR(128) PRIMARY KEY,
        source VARCHAR(64) NOT NULL,
        source_event_id VARCHAR(128) NOT NULL,
        event_type VARCHAR(64) NOT NULL,
        timestamp VARCHAR(64) NOT NULL,
        received_at VARCHAR(64) NOT NULL,
        entity_type VARCHAR(64) NOT NULL,
        entity_id VARCHAR(128) NOT NULL,
        repository VARCHAR(256) NOT NULL,
        commit_hash VARCHAR(128) NOT NULL,
        release_id VARCHAR(128) NOT NULL,
        work_item_id VARCHAR(128) NOT NULL,
        service_id VARCHAR(128) NOT NULL,
        environment VARCHAR(64) NOT NULL,
        correlation_keys_json TEXT NOT NULL DEFAULT '{}',
        payload_json TEXT NOT NULL DEFAULT '{}',
        provenance_json TEXT NOT NULL DEFAULT '{}',
        processing_status VARCHAR(32) NOT NULL DEFAULT 'PENDING',
        attempt_count INTEGER NOT NULL DEFAULT 0,
        correlation_id VARCHAR(128) NOT NULL DEFAULT ''
    );
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_pg_event_release ON event_journal(release_id);
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_pg_event_type ON event_journal(event_type);
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_pg_event_commit ON event_journal(commit_hash);
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_pg_event_received ON event_journal(received_at);
    """,

    """
    CREATE TABLE IF NOT EXISTS event_idempotency (
        idempotency_key VARCHAR(128) PRIMARY KEY,
        event_id VARCHAR(128) NOT NULL,
        source VARCHAR(64) NOT NULL,
        source_event_id VARCHAR(128) NOT NULL,
        event_type VARCHAR(64) NOT NULL,
        registered_at VARCHAR(64) NOT NULL,
        ttl_seconds INTEGER DEFAULT NULL,
        CONSTRAINT uq_pg_event_identity UNIQUE (source, source_event_id, event_type)
    );
    """,

    """
    CREATE TABLE IF NOT EXISTS investigations (
        investigation_id VARCHAR(128) PRIMARY KEY,
        release_id VARCHAR(128) NOT NULL,
        service_name VARCHAR(128) NOT NULL,
        version VARCHAR(64) NOT NULL,
        commit_hash VARCHAR(128) NOT NULL,
        status VARCHAR(32) NOT NULL DEFAULT 'PENDING',
        created_at VARCHAR(64) NOT NULL,
        updated_at VARCHAR(64) NOT NULL,
        candidate_json TEXT NOT NULL,
        outages_json TEXT NOT NULL DEFAULT '[]',
        telemetry_json TEXT NOT NULL DEFAULT '{}'
    );
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_pg_inv_release ON investigations(release_id);
    """,

    """
    CREATE TABLE IF NOT EXISTS investigation_gaps (
        investigation_id VARCHAR(128) NOT NULL,
        gap_id VARCHAR(128) NOT NULL,
        gap_type VARCHAR(64) NOT NULL,
        target_entity VARCHAR(128) NOT NULL,
        description TEXT NOT NULL,
        why_needed TEXT NOT NULL,
        required_information TEXT NOT NULL,
        is_blocking INTEGER NOT NULL DEFAULT 1,
        status VARCHAR(64) NOT NULL DEFAULT 'OPEN',
        resolution TEXT NOT NULL DEFAULT '',
        resolution_evidence_ids_json TEXT NOT NULL DEFAULT '[]',
        updated_at VARCHAR(64) NOT NULL,
        PRIMARY KEY (investigation_id, gap_id),
        FOREIGN KEY (investigation_id) REFERENCES investigations(investigation_id) ON DELETE CASCADE
    );
    """,

    """
    CREATE TABLE IF NOT EXISTS evidence_store (
        evidence_id VARCHAR(128) PRIMARY KEY,
        investigation_id VARCHAR(128) DEFAULT NULL,
        source VARCHAR(64) NOT NULL,
        source_type VARCHAR(64) NOT NULL,
        content_hash VARCHAR(128) NOT NULL,
        canonical_uri TEXT NOT NULL,
        entity_type VARCHAR(64) NOT NULL,
        entity_id VARCHAR(128) NOT NULL,
        commit_hash VARCHAR(128) NOT NULL,
        version VARCHAR(64) NOT NULL,
        valid_from VARCHAR(64) NOT NULL,
        valid_until VARCHAR(64) DEFAULT NULL,
        state VARCHAR(32) NOT NULL DEFAULT 'VALID',
        metadata_json TEXT NOT NULL DEFAULT '{}',
        created_at VARCHAR(64) NOT NULL
    );
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_pg_evidence_inv ON evidence_store(investigation_id);
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_pg_evidence_validity ON evidence_store(valid_until, state);
    """,

    """
    CREATE TABLE IF NOT EXISTS evidence_lifecycle (
        id SERIAL PRIMARY KEY,
        evidence_id VARCHAR(128) NOT NULL,
        state VARCHAR(32) NOT NULL,
        transition_timestamp VARCHAR(64) NOT NULL,
        reason TEXT NOT NULL,
        superseded_by VARCHAR(128) DEFAULT NULL,
        causal_event_id VARCHAR(128) DEFAULT NULL,
        FOREIGN KEY (evidence_id) REFERENCES evidence_store(evidence_id) ON DELETE CASCADE
    );
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_pg_lifecycle_evidence ON evidence_lifecycle(evidence_id);
    """,

    """
    CREATE TABLE IF NOT EXISTS decisions (
        decision_id VARCHAR(128) PRIMARY KEY,
        investigation_id VARCHAR(128) NOT NULL,
        release_id VARCHAR(128) NOT NULL,
        outcome VARCHAR(32) NOT NULL,
        risk_level VARCHAR(32) NOT NULL,
        confidence REAL NOT NULL,
        rationale TEXT NOT NULL,
        blocking_factors_json TEXT NOT NULL DEFAULT '[]',
        verified_factors_json TEXT NOT NULL DEFAULT '[]',
        recommendations_json TEXT NOT NULL DEFAULT '[]',
        governed_actions_json TEXT NOT NULL DEFAULT '[]',
        evidence_ids_json TEXT NOT NULL DEFAULT '[]',
        contradiction_ids_json TEXT NOT NULL DEFAULT '[]',
        unresolved_gap_ids_json TEXT NOT NULL DEFAULT '[]',
        decision_timestamp VARCHAR(64) NOT NULL,
        provenance_json TEXT NOT NULL DEFAULT '{}'
    );
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_pg_decision_release ON decisions(release_id, decision_timestamp);
    """,

    """
    CREATE TABLE IF NOT EXISTS decision_lineage (
        change_id VARCHAR(128) PRIMARY KEY,
        release_id VARCHAR(128) NOT NULL,
        previous_outcome VARCHAR(32) NOT NULL,
        new_outcome VARCHAR(32) NOT NULL,
        trigger_event_id VARCHAR(128) NOT NULL,
        changed_evidence_ids_json TEXT NOT NULL DEFAULT '[]',
        explanation TEXT NOT NULL,
        timestamp VARCHAR(64) NOT NULL
    );
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_pg_lineage_release ON decision_lineage(release_id, timestamp);
    """,

    """
    CREATE TABLE IF NOT EXISTS governed_actions (
        action_id VARCHAR(128) PRIMARY KEY,
        action_type VARCHAR(64) NOT NULL,
        target_system VARCHAR(64) NOT NULL,
        payload_json TEXT NOT NULL DEFAULT '{}',
        status VARCHAR(32) NOT NULL DEFAULT 'PROPOSED',
        idempotency_key VARCHAR(128) NOT NULL DEFAULT '',
        requires_human_approval INTEGER NOT NULL DEFAULT 1,
        authorized_by VARCHAR(128) DEFAULT NULL,
        execution_timestamp VARCHAR(64) DEFAULT NULL,
        audit_trail_json TEXT NOT NULL DEFAULT '[]',
        created_at VARCHAR(64) NOT NULL
    );
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_pg_action_idemp ON governed_actions(idempotency_key);
    """,

    """
    CREATE TABLE IF NOT EXISTS governed_action_executions (
        idempotency_key VARCHAR(128) PRIMARY KEY,
        action_id VARCHAR(128) NOT NULL,
        result_payload_json TEXT NOT NULL DEFAULT '{}',
        executed_at VARCHAR(64) NOT NULL
    );
    """,

    """
    CREATE TABLE IF NOT EXISTS worker_leases (
        task_id VARCHAR(128) PRIMARY KEY,
        task_type VARCHAR(64) NOT NULL,
        payload_json TEXT NOT NULL DEFAULT '{}',
        worker_id VARCHAR(128) DEFAULT NULL,
        status VARCHAR(32) NOT NULL DEFAULT 'PENDING',
        attempt_count INTEGER NOT NULL DEFAULT 0,
        claimed_at VARCHAR(64) DEFAULT NULL,
        lease_until VARCHAR(64) DEFAULT NULL,
        heartbeat_at VARCHAR(64) DEFAULT NULL,
        completed_at VARCHAR(64) DEFAULT NULL,
        result_json TEXT DEFAULT NULL
    );
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_pg_worker_queue ON worker_leases(status, lease_until);
    """,

    """
    CREATE TABLE IF NOT EXISTS graph_nodes (
        node_id VARCHAR(256) NOT NULL,
        node_type VARCHAR(64) NOT NULL,
        properties_json TEXT NOT NULL DEFAULT '{}',
        valid_from VARCHAR(64) NOT NULL,
        valid_until VARCHAR(64) DEFAULT NULL,
        is_active INTEGER NOT NULL DEFAULT 1,
        updated_at VARCHAR(64) NOT NULL,
        PRIMARY KEY (node_id, valid_from)
    );
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_pg_nodes_temporal ON graph_nodes(valid_from, valid_until, is_active);
    """,
    """
    CREATE TABLE IF NOT EXISTS graph_edges (
        source_id VARCHAR(256) NOT NULL,
        target_id VARCHAR(256) NOT NULL,
        edge_type VARCHAR(64) NOT NULL,
        properties_json TEXT NOT NULL DEFAULT '{}',
        valid_from VARCHAR(64) NOT NULL,
        valid_until VARCHAR(64) DEFAULT NULL,
        is_active INTEGER NOT NULL DEFAULT 1,
        updated_at VARCHAR(64) NOT NULL,
        PRIMARY KEY (source_id, target_id, edge_type, valid_from)
    );
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_pg_edges_temporal ON graph_edges(valid_from, valid_until, is_active);
    """,

    """
    CREATE TABLE IF NOT EXISTS entity_candidates (
        release_id VARCHAR(128) PRIMARY KEY,
        service_name VARCHAR(128) NOT NULL,
        version VARCHAR(64) NOT NULL,
        repository VARCHAR(256) NOT NULL,
        branch VARCHAR(128) NOT NULL DEFAULT 'main',
        commit_hash VARCHAR(128) NOT NULL,
        target_environment VARCHAR(64) NOT NULL DEFAULT 'production',
        pull_request_id VARCHAR(64) DEFAULT NULL,
        linked_work_items_json TEXT NOT NULL DEFAULT '[]',
        changed_components_json TEXT NOT NULL DEFAULT '[]',
        candidate_json TEXT NOT NULL,
        created_at VARCHAR(64) NOT NULL
    );
    """,

    """
    CREATE TABLE IF NOT EXISTS audit_journal (
        audit_id VARCHAR(128) PRIMARY KEY,
        timestamp VARCHAR(64) NOT NULL,
        actor VARCHAR(128) NOT NULL,
        action VARCHAR(64) NOT NULL,
        entity_type VARCHAR(64) NOT NULL,
        entity_id VARCHAR(128) NOT NULL,
        details_json TEXT NOT NULL DEFAULT '{}',
        correlation_id VARCHAR(128) NOT NULL DEFAULT ''
    );
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_pg_audit_entity ON audit_journal(entity_type, entity_id);
    """,

    """
    CREATE TABLE IF NOT EXISTS schema_migrations (
        version INTEGER PRIMARY KEY,
        name VARCHAR(128) NOT NULL,
        applied_at VARCHAR(64) NOT NULL
    );
    """
]


# -----------------------------------------------------------------------------
# BRICK 4.5 — OPERATIONAL & DISTRIBUTED CONTROL PLANE (MIGRATION V2)
# -----------------------------------------------------------------------------

SQLITE_SCHEMA_V2 = [
    # 1. Multi-tenant columns and indexes
    "ALTER TABLE event_journal ADD COLUMN tenant_id TEXT NOT NULL DEFAULT 'default';",
    "CREATE INDEX IF NOT EXISTS idx_event_tenant ON event_journal(tenant_id, release_id);",

    "ALTER TABLE investigations ADD COLUMN tenant_id TEXT NOT NULL DEFAULT 'default';",
    "CREATE INDEX IF NOT EXISTS idx_inv_tenant ON investigations(tenant_id, release_id);",

    "ALTER TABLE evidence_store ADD COLUMN tenant_id TEXT NOT NULL DEFAULT 'default';",
    "CREATE INDEX IF NOT EXISTS idx_ev_tenant ON evidence_store(tenant_id, entity_id);",

    "ALTER TABLE decisions ADD COLUMN tenant_id TEXT NOT NULL DEFAULT 'default';",
    "CREATE INDEX IF NOT EXISTS idx_dec_tenant ON decisions(tenant_id, release_id);",

    "ALTER TABLE decision_lineage ADD COLUMN tenant_id TEXT NOT NULL DEFAULT 'default';",
    "CREATE INDEX IF NOT EXISTS idx_lineage_tenant ON decision_lineage(tenant_id, release_id);",

    "ALTER TABLE governed_actions ADD COLUMN tenant_id TEXT NOT NULL DEFAULT 'default';",
    "CREATE INDEX IF NOT EXISTS idx_actions_tenant ON governed_actions(tenant_id, status);",

    "ALTER TABLE worker_leases ADD COLUMN tenant_id TEXT NOT NULL DEFAULT 'default';",
    "CREATE INDEX IF NOT EXISTS idx_leases_tenant ON worker_leases(tenant_id, status);",

    "ALTER TABLE graph_nodes ADD COLUMN tenant_id TEXT NOT NULL DEFAULT 'default';",
    "CREATE INDEX IF NOT EXISTS idx_nodes_tenant ON graph_nodes(tenant_id, node_id);",

    "ALTER TABLE graph_edges ADD COLUMN tenant_id TEXT NOT NULL DEFAULT 'default';",
    "CREATE INDEX IF NOT EXISTS idx_edges_tenant ON graph_edges(tenant_id, source_id, target_id);",

    "ALTER TABLE entity_candidates ADD COLUMN tenant_id TEXT NOT NULL DEFAULT 'default';",
    "CREATE INDEX IF NOT EXISTS idx_candidates_tenant ON entity_candidates(tenant_id, release_id);",

    # 2. Webhook Registrations Table
    """
    CREATE TABLE IF NOT EXISTS webhook_registrations (
        registration_id TEXT PRIMARY KEY,
        tenant_id TEXT NOT NULL DEFAULT 'default',
        provider TEXT NOT NULL,
        external_registration_id TEXT NOT NULL,
        target_entity TEXT NOT NULL,
        callback_url TEXT NOT NULL,
        secret_token TEXT NOT NULL DEFAULT '',
        event_types_json TEXT NOT NULL DEFAULT '[]',
        status TEXT NOT NULL DEFAULT 'REGISTERED',
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        last_verified_at TEXT DEFAULT NULL,
        provenance_json TEXT NOT NULL DEFAULT '{}'
    );
    """,
    "CREATE INDEX IF NOT EXISTS idx_webhook_tenant ON webhook_registrations(tenant_id, provider);",
    "CREATE INDEX IF NOT EXISTS idx_webhook_target ON webhook_registrations(target_entity);",

    # 3. Distributed Locks Table
    """
    CREATE TABLE IF NOT EXISTS distributed_locks (
        lock_key TEXT PRIMARY KEY,
        tenant_id TEXT NOT NULL DEFAULT 'default',
        owner TEXT NOT NULL,
        fencing_token INTEGER NOT NULL DEFAULT 1,
        acquired_at TEXT NOT NULL,
        expires_at REAL NOT NULL,
        metadata_json TEXT NOT NULL DEFAULT '{}'
    );
    """,
    "CREATE INDEX IF NOT EXISTS idx_lock_tenant ON distributed_locks(tenant_id, lock_key);",
]

POSTGRES_SCHEMA_V2 = [
    # 1. Multi-tenant columns and indexes
    "ALTER TABLE event_journal ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(128) NOT NULL DEFAULT 'default';",
    "CREATE INDEX IF NOT EXISTS idx_pg_event_tenant ON event_journal(tenant_id, release_id);",

    "ALTER TABLE investigations ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(128) NOT NULL DEFAULT 'default';",
    "CREATE INDEX IF NOT EXISTS idx_pg_inv_tenant ON investigations(tenant_id, release_id);",

    "ALTER TABLE evidence_store ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(128) NOT NULL DEFAULT 'default';",
    "CREATE INDEX IF NOT EXISTS idx_pg_ev_tenant ON evidence_store(tenant_id, entity_id);",

    "ALTER TABLE decisions ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(128) NOT NULL DEFAULT 'default';",
    "CREATE INDEX IF NOT EXISTS idx_pg_dec_tenant ON decisions(tenant_id, release_id);",

    "ALTER TABLE decision_lineage ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(128) NOT NULL DEFAULT 'default';",
    "CREATE INDEX IF NOT EXISTS idx_pg_lineage_tenant ON decision_lineage(tenant_id, release_id);",

    "ALTER TABLE governed_actions ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(128) NOT NULL DEFAULT 'default';",
    "CREATE INDEX IF NOT EXISTS idx_pg_actions_tenant ON governed_actions(tenant_id, status);",

    "ALTER TABLE worker_leases ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(128) NOT NULL DEFAULT 'default';",
    "CREATE INDEX IF NOT EXISTS idx_pg_leases_tenant ON worker_leases(tenant_id, status);",

    "ALTER TABLE graph_nodes ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(128) NOT NULL DEFAULT 'default';",
    "CREATE INDEX IF NOT EXISTS idx_pg_nodes_tenant ON graph_nodes(tenant_id, node_id);",

    "ALTER TABLE graph_edges ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(128) NOT NULL DEFAULT 'default';",
    "CREATE INDEX IF NOT EXISTS idx_pg_edges_tenant ON graph_edges(tenant_id, source_id, target_id);",

    "ALTER TABLE entity_candidates ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(128) NOT NULL DEFAULT 'default';",
    "CREATE INDEX IF NOT EXISTS idx_pg_candidates_tenant ON entity_candidates(tenant_id, release_id);",

    # 2. Webhook Registrations Table
    """
    CREATE TABLE IF NOT EXISTS webhook_registrations (
        registration_id VARCHAR(128) PRIMARY KEY,
        tenant_id VARCHAR(128) NOT NULL DEFAULT 'default',
        provider VARCHAR(64) NOT NULL,
        external_registration_id VARCHAR(128) NOT NULL,
        target_entity VARCHAR(256) NOT NULL,
        callback_url VARCHAR(512) NOT NULL,
        secret_token VARCHAR(256) NOT NULL DEFAULT '',
        event_types_json TEXT NOT NULL DEFAULT '[]',
        status VARCHAR(64) NOT NULL DEFAULT 'REGISTERED',
        created_at VARCHAR(64) NOT NULL,
        updated_at VARCHAR(64) NOT NULL,
        last_verified_at VARCHAR(64) DEFAULT NULL,
        provenance_json TEXT NOT NULL DEFAULT '{}'
    );
    """,
    "CREATE INDEX IF NOT EXISTS idx_pg_webhook_tenant ON webhook_registrations(tenant_id, provider);",
    "CREATE INDEX IF NOT EXISTS idx_pg_webhook_target ON webhook_registrations(target_entity);",

    # 3. Distributed Locks Table
    """
    CREATE TABLE IF NOT EXISTS distributed_locks (
        lock_key VARCHAR(128) PRIMARY KEY,
        tenant_id VARCHAR(128) NOT NULL DEFAULT 'default',
        owner VARCHAR(128) NOT NULL,
        fencing_token BIGINT NOT NULL DEFAULT 1,
        acquired_at VARCHAR(64) NOT NULL,
        expires_at DOUBLE PRECISION NOT NULL,
        metadata_json TEXT NOT NULL DEFAULT '{}'
    );
    """,
    "CREATE INDEX IF NOT EXISTS idx_pg_lock_tenant ON distributed_locks(tenant_id, lock_key);",

    # 4. Build Artifacts & Deployments (Brick 4.8)
    """
    CREATE TABLE IF NOT EXISTS build_artifacts (
        artifact_digest VARCHAR(256) PRIMARY KEY,
        tenant_id VARCHAR(128) NOT NULL DEFAULT 'default',
        artifact_id VARCHAR(128) NOT NULL,
        artifact_name VARCHAR(256) NOT NULL DEFAULT '',
        repository VARCHAR(256) NOT NULL,
        commit_hash VARCHAR(128) NOT NULL,
        build_id VARCHAR(128) NOT NULL DEFAULT '',
        built_at VARCHAR(64) NOT NULL,
        payload_json TEXT NOT NULL DEFAULT '{}'
    );
    """,
    "CREATE INDEX IF NOT EXISTS idx_pg_art_tenant_commit ON build_artifacts(tenant_id, repository, commit_hash);",

    """
    CREATE TABLE IF NOT EXISTS deployments (
        deployment_id VARCHAR(128) PRIMARY KEY,
        tenant_id VARCHAR(128) NOT NULL DEFAULT 'default',
        service_id VARCHAR(128) NOT NULL,
        environment VARCHAR(64) NOT NULL DEFAULT 'PRODUCTION',
        artifact_digest VARCHAR(256) NOT NULL,
        commit_hash VARCHAR(128) NOT NULL,
        deployed_at VARCHAR(64) NOT NULL,
        status VARCHAR(64) NOT NULL DEFAULT 'ACTIVE',
        payload_json TEXT NOT NULL DEFAULT '{}'
    );
    """,
    "CREATE INDEX IF NOT EXISTS idx_pg_dep_tenant_service ON deployments(tenant_id, service_id, environment);",

    """
    CREATE TABLE IF NOT EXISTS runtime_services (
        service_id VARCHAR(128) PRIMARY KEY,
        tenant_id VARCHAR(128) NOT NULL DEFAULT 'default',
        service_name VARCHAR(128) NOT NULL,
        environment VARCHAR(64) NOT NULL DEFAULT 'PRODUCTION',
        exposure VARCHAR(64) NOT NULL DEFAULT 'UNKNOWN',
        auth_required VARCHAR(64) NOT NULL DEFAULT 'UNKNOWN',
        payload_json TEXT NOT NULL DEFAULT '{}'
    );
    """,
    "CREATE INDEX IF NOT EXISTS idx_pg_svc_tenant_env ON runtime_services(tenant_id, environment);",

    # 5. Security Intelligence Entities (Brick 4.8)
    """
    CREATE TABLE IF NOT EXISTS security_findings (
        finding_id VARCHAR(128) PRIMARY KEY,
        tenant_id VARCHAR(128) NOT NULL DEFAULT 'default',
        repository VARCHAR(256) NOT NULL,
        commit_hash VARCHAR(128) NOT NULL,
        artifact_digest VARCHAR(256) DEFAULT NULL,
        severity VARCHAR(32) NOT NULL,
        category VARCHAR(64) NOT NULL,
        status VARCHAR(64) NOT NULL DEFAULT 'ACTIVE',
        payload_json TEXT NOT NULL DEFAULT '{}'
    );
    """,
    "CREATE INDEX IF NOT EXISTS idx_pg_sec_finding_tenant ON security_findings(tenant_id, repository, commit_hash);",
    "CREATE INDEX IF NOT EXISTS idx_pg_sec_finding_artifact ON security_findings(artifact_digest);",

    """
    CREATE TABLE IF NOT EXISTS security_impact_assessments (
        assessment_id VARCHAR(128) PRIMARY KEY,
        finding_id VARCHAR(128) NOT NULL,
        tenant_id VARCHAR(128) NOT NULL DEFAULT 'default',
        repository VARCHAR(256) NOT NULL,
        commit_hash VARCHAR(128) NOT NULL,
        artifact_digest VARCHAR(256) DEFAULT NULL,
        impact_level VARCHAR(64) NOT NULL,
        business_impact VARCHAR(64) NOT NULL,
        payload_json TEXT NOT NULL DEFAULT '{}'
    );
    """,
    "CREATE INDEX IF NOT EXISTS idx_pg_sec_imp_finding ON security_impact_assessments(finding_id);",

    """
    CREATE TABLE IF NOT EXISTS security_investigations (
        investigation_id VARCHAR(128) PRIMARY KEY,
        tenant_id VARCHAR(128) NOT NULL DEFAULT 'default',
        repository VARCHAR(256) NOT NULL,
        commit_hash VARCHAR(128) NOT NULL,
        artifact_digest VARCHAR(256) DEFAULT NULL,
        decision_outcome VARCHAR(64) NOT NULL DEFAULT 'SECURITY_UNKNOWN',
        created_at VARCHAR(64) NOT NULL,
        payload_json TEXT NOT NULL DEFAULT '{}'
    );
    """,
    "CREATE INDEX IF NOT EXISTS idx_pg_sec_inv_tenant ON security_investigations(tenant_id, repository, commit_hash);",

    """
    CREATE TABLE IF NOT EXISTS security_decisions (
        decision_id VARCHAR(128) PRIMARY KEY,
        tenant_id VARCHAR(128) NOT NULL DEFAULT 'default',
        repository VARCHAR(256) NOT NULL,
        commit_hash VARCHAR(128) NOT NULL,
        artifact_digest VARCHAR(256) DEFAULT NULL,
        outcome VARCHAR(64) NOT NULL,
        risk_level VARCHAR(32) NOT NULL,
        created_at VARCHAR(64) NOT NULL,
        payload_json TEXT NOT NULL DEFAULT '{}'
    );
    """,
    "CREATE INDEX IF NOT EXISTS idx_pg_sec_dec_tenant ON security_decisions(tenant_id, repository, commit_hash);",

    """
    CREATE TABLE IF NOT EXISTS security_verifications (
        verification_id VARCHAR(128) PRIMARY KEY,
        finding_id VARCHAR(128) NOT NULL,
        tenant_id VARCHAR(128) NOT NULL DEFAULT 'default',
        rescan_commit VARCHAR(128) NOT NULL,
        rescan_artifact_digest VARCHAR(256) DEFAULT NULL,
        status VARCHAR(64) NOT NULL,
        verified_at VARCHAR(64) NOT NULL,
        payload_json TEXT NOT NULL DEFAULT '{}'
    );
    """,
    "CREATE INDEX IF NOT EXISTS idx_pg_sec_ver_finding ON security_verifications(finding_id);"
]


