"""
ORACLE Release Readiness Configuration & Provider Factory (Brick 4.2)

Establishes first-class runtime modes:
- OFFLINE: In-memory simulation / local fixtures (zero network calls)
- LIVE: Real external enterprise APIs (GitHub, Jira Cloud, GitHub Actions, Semgrep/Trivy)
- HYBRID: Selectively mix live and offline providers for staged rollouts

Enforces:
1. Dependency injection over scattered environment checks.
2. Configurable Jira field mappings to handle enterprise schema variability without controller leaks.
3. Fail-closed policy for live external writes (LIVE_ACTIONS must be explicitly enabled).
"""

from __future__ import annotations

import os
from enum import Enum
from typing import Any, Dict, List, Optional
import httpx
from pydantic import BaseModel, Field

from backend.release.connectivity.credentials import (
    CredentialProvider,
    EnvCredentialProvider,
)
from backend.release.providers import (
    BaseReleaseDataProvider,
    InMemoryReleaseDataProvider,
)


class ProviderMode(str, Enum):
    """Execution mode for enterprise connectivity."""
    OFFLINE = "offline"
    LIVE    = "live"
    HYBRID  = "hybrid"


class JiraFieldMappingConfig(BaseModel):
    """
    Configurable mapping for Jira Cloud REST API v3 schemas.
    Decouples custom field keys and status names from canonical ORACLE models.
    """
    summary_field: str = "summary"
    status_field: str = "status"
    priority_field: str = "priority"
    issuetype_field: str = "issuetype"
    labels_field: str = "labels"
    assignee_field: str = "assignee"
    created_field: str = "created"

    # Custom field IDs used across enterprise Jira instances for approvals/rejections
    approval_fields: List[str] = Field(
        default_factory=lambda: ["customfield_10020", "customfield_approvals"]
    )
    rejection_fields: List[str] = Field(
        default_factory=lambda: ["customfield_10021", "customfield_rejections"]
    )

    # Status names that map to canonical WorkItemStatus
    done_status_names: List[str] = Field(
        default_factory=lambda: ["DONE", "CLOSED", "RESOLVED", "VERIFIED"]
    )
    blocked_status_names: List[str] = Field(
        default_factory=lambda: ["BLOCKED", "IMPEDED", "WAITING", "ON HOLD"]
    )
    rejected_status_names: List[str] = Field(
        default_factory=lambda: ["REJECTED", "WONTFIX", "CANCELLED", "DECLINED"]
    )
    in_progress_status_names: List[str] = Field(
        default_factory=lambda: ["IN PROGRESS", "IN REVIEW", "DEV COMPLETE", "UNDER TEST"]
    )

    # Priority names considered blocking
    blocking_priorities: List[str] = Field(
        default_factory=lambda: ["BLOCKER", "CRITICAL", "P0", "P1"]
    )

    # JQL template for active service incidents
    incident_jql_template: str = 'text ~ "{service_name}" AND issuetype in (Incident, Bug) AND statusCategory != Done'


class OracleReleaseConfig(BaseModel):
    """
    Central configuration for Release Readiness Intelligence and Live Enterprise Pilot.
    Can be created programmatically or loaded from environment variables.
    """
    provider_mode: ProviderMode = ProviderMode.OFFLINE
    live_actions_enabled: bool = False   # Fail-closed: live writes disabled by default
    dry_run_actions: bool = True         # Live actions run in dry-run mode unless explicitly False

    # Base URLs for external enterprise APIs
    github_base_url: str = "https://api.github.com"
    jira_base_url: str = "https://corp.atlassian.net"

    # Field mapping
    jira_field_mapping: JiraFieldMappingConfig = Field(default_factory=JiraFieldMappingConfig)

    # Security scanner choice: "semgrep" or "trivy"
    security_scanner: str = "semgrep"

    # Optional explicit credential provider (injected dependency)
    credential_provider: Optional[Any] = None

    model_config = {"arbitrary_types_allowed": True}

    @classmethod
    def from_env(cls, credential_provider: Optional[CredentialProvider] = None) -> OracleReleaseConfig:
        """Construct configuration from environment variables."""
        raw_mode = os.getenv("ORACLE_PROVIDER_MODE", "offline").lower()
        if raw_mode in ("live", "production"):
            mode = ProviderMode.LIVE
        elif raw_mode == "hybrid":
            mode = ProviderMode.HYBRID
        else:
            mode = ProviderMode.OFFLINE

        live_actions_val = os.getenv("ORACLE_LIVE_ACTIONS_ENABLED", "false").lower()
        live_actions = live_actions_val in ("1", "true", "yes", "enabled")

        dry_run_val = os.getenv("ORACLE_DRY_RUN_ACTIONS", "true").lower()
        dry_run = dry_run_val in ("1", "true", "yes")

        github_url = os.getenv("GITHUB_BASE_URL", "https://api.github.com")
        jira_url = os.getenv("JIRA_BASE_URL", "https://corp.atlassian.net")
        scanner = os.getenv("ORACLE_SECURITY_SCANNER", "semgrep").lower()

        cred_prov = credential_provider or EnvCredentialProvider()

        return cls(
            provider_mode=mode,
            live_actions_enabled=live_actions,
            dry_run_actions=dry_run,
            github_base_url=github_url,
            jira_base_url=jira_url,
            security_scanner=scanner,
            credential_provider=cred_prov,
        )


class ProviderFactory:
    """
    Dependency-injected factory constructing the appropriate release data provider
    based on authoritative OracleReleaseConfig.
    """

    @staticmethod
    def create_provider(
        config: Optional[OracleReleaseConfig] = None,
        transport: Optional[httpx.BaseTransport] = None,
    ) -> BaseReleaseDataProvider:
        """
        Create a release data provider conforming to BaseReleaseDataProvider.
        - OFFLINE: Returns InMemoryReleaseDataProvider
        - LIVE / HYBRID: Returns EnterpriseReleaseDataProvider configured with real connectors
        """
        cfg = config or OracleReleaseConfig()

        if cfg.provider_mode == ProviderMode.OFFLINE:
            return InMemoryReleaseDataProvider()

        # Import lazily to prevent circular dependencies
        from backend.release.connectivity.composite import EnterpriseReleaseDataProvider
        from backend.release.connectivity.github import GitHubReleaseProvider
        from backend.release.connectivity.github_actions import GitHubActionsCICDProvider
        from backend.release.connectivity.jira import JiraWorkManagementProvider
        from backend.release.connectivity.security import (
            SemgrepSecurityProvider,
            TrivySecurityProvider,
        )

        cred_provider = cfg.credential_provider or EnvCredentialProvider()

        git_prov = GitHubReleaseProvider(
            credential_provider=cred_provider,
            base_url=cfg.github_base_url,
            transport=transport,
        )

        work_prov = JiraWorkManagementProvider(
            credential_provider=cred_provider,
            base_url=cfg.jira_base_url,
            mapping_config=cfg.jira_field_mapping,
            transport=transport,
        )

        ci_prov = GitHubActionsCICDProvider(
            credential_provider=cred_provider,
            base_url=cfg.github_base_url,
            transport=transport,
        )

        if cfg.security_scanner == "trivy":
            sec_prov = TrivySecurityProvider()
        else:
            sec_prov = SemgrepSecurityProvider()

        return EnterpriseReleaseDataProvider(
            git_provider=git_prov,
            work_provider=work_prov,
            ci_provider=ci_prov,
            security_provider=sec_prov,
        )


# =============================================================================
# ENTERPRISE RUNTIME CONFIGURATION (Brick 4.6)
# =============================================================================

class DatabaseConfig(BaseModel):
    """Database persistence configuration."""
    backend: str = "sqlite"              # "sqlite" or "postgres"
    url: Optional[str] = None           # Connection URI (postgresql://... or path to sqlite)
    pool_size: int = 5
    max_overflow: int = 10
    timeout_seconds: float = 30.0
    ssl_mode: str = "prefer"


class RedisConfig(BaseModel):
    """Ephemeral Redis coordination configuration."""
    enabled: bool = False
    url: str = "redis://localhost:6379/0"
    fallback_to_db: bool = True
    cluster_mode: bool = False


class WebhookConfig(BaseModel):
    """Network ingress & webhook validation parameters."""
    secret_token: Optional[str] = None
    max_drift_seconds: int = 300
    max_payload_bytes: int = 1_048_576   # 1MB strict limit


class WorkerConfig(BaseModel):
    """Worker node dispatch & execution parameters."""
    node_id: Optional[str] = None
    concurrency: int = 4
    lease_duration_seconds: int = 30
    heartbeat_interval_seconds: float = 5.0
    task_timeout_seconds: float = 120.0


class SecurityConfig(BaseModel):
    """Runtime security controls and secret backend settings."""
    secret_store_type: str = "env"       # "env", "kubernetes", "memory"
    allowed_hosts: List[str] = Field(default_factory=lambda: ["*"])
    require_https: bool = False
    read_only_root_fs: bool = False


class ObservabilityConfig(BaseModel):
    """Prometheus metrics & OpenTelemetry distributed tracing."""
    prometheus_enabled: bool = True
    tracing_enabled: bool = True
    otel_endpoint: Optional[str] = None
    sample_rate: float = 1.0


class IngressConfig(BaseModel):
    """HTTP Ingress network parameters."""
    host: str = "0.0.0.0"
    port: int = 8000
    trusted_proxies: List[str] = Field(default_factory=lambda: ["127.0.0.1", "::1"])
    correlation_header: str = "X-Correlation-ID"


class TenancyConfig(BaseModel):
    """Multi-tenant boundary enforcement."""
    default_tenant_id: str = "default"
    enforce_multi_tenancy: bool = True


class EnterpriseRuntimeConfig(BaseModel):
    """
    Centralized, validated configuration for ORACLE 4.6 Enterprise Runtime.
    Enforces fail-closed startup validation in production environments.
    """
    environment: str = "development"     # "development", "test", "production"
    version: str = "4.6.0"
    database: DatabaseConfig = Field(default_factory=DatabaseConfig)
    redis: RedisConfig = Field(default_factory=RedisConfig)
    webhook: WebhookConfig = Field(default_factory=WebhookConfig)
    worker: WorkerConfig = Field(default_factory=WorkerConfig)
    security: SecurityConfig = Field(default_factory=SecurityConfig)
    observability: ObservabilityConfig = Field(default_factory=ObservabilityConfig)
    ingress: IngressConfig = Field(default_factory=IngressConfig)
    tenancy: TenancyConfig = Field(default_factory=TenancyConfig)
    release: OracleReleaseConfig = Field(default_factory=OracleReleaseConfig)

    model_config = {"arbitrary_types_allowed": True}

    @classmethod
    def from_env(cls) -> EnterpriseRuntimeConfig:
        """Construct complete enterprise runtime configuration from environment."""
        env = os.getenv("ORACLE_ENV", "development").lower()

        # Database
        db_backend = os.getenv("ORACLE_DB_BACKEND", "sqlite").lower()
        db_url = os.getenv("ORACLE_DATABASE_URL") or os.getenv("DATABASE_URL")
        db_config = DatabaseConfig(
            backend=db_backend,
            url=db_url,
            pool_size=int(os.getenv("ORACLE_DB_POOL_SIZE", "5")),
            timeout_seconds=float(os.getenv("ORACLE_DB_TIMEOUT", "30.0")),
            ssl_mode=os.getenv("ORACLE_DB_SSL_MODE", "prefer"),
        )

        # Redis
        redis_enabled = os.getenv("ORACLE_REDIS_ENABLED", "false").lower() in ("1", "true", "yes")
        redis_url = os.getenv("ORACLE_REDIS_URL") or os.getenv("REDIS_URL", "redis://localhost:6379/0")
        redis_config = RedisConfig(
            enabled=redis_enabled,
            url=redis_url,
            fallback_to_db=os.getenv("ORACLE_REDIS_FALLBACK", "true").lower() in ("1", "true", "yes"),
            cluster_mode=os.getenv("ORACLE_REDIS_CLUSTER", "false").lower() in ("1", "true", "yes"),
        )

        # Webhooks
        webhook_config = WebhookConfig(
            secret_token=os.getenv("ORACLE_WEBHOOK_SECRET"),
            max_drift_seconds=int(os.getenv("ORACLE_WEBHOOK_MAX_DRIFT", "300")),
            max_payload_bytes=int(os.getenv("ORACLE_WEBHOOK_MAX_PAYLOAD", "1048576")),
        )

        # Worker
        worker_config = WorkerConfig(
            node_id=os.getenv("ORACLE_NODE_ID"),
            concurrency=int(os.getenv("ORACLE_WORKER_CONCURRENCY", "4")),
            lease_duration_seconds=int(os.getenv("ORACLE_WORKER_LEASE_DURATION", "30")),
            heartbeat_interval_seconds=float(os.getenv("ORACLE_WORKER_HEARTBEAT_INTERVAL", "5.0")),
        )

        # Security
        security_config = SecurityConfig(
            secret_store_type=os.getenv("ORACLE_SECRET_STORE", "env").lower(),
            require_https=os.getenv("ORACLE_REQUIRE_HTTPS", "false").lower() in ("1", "true", "yes"),
            read_only_root_fs=os.getenv("ORACLE_READ_ONLY_ROOT_FS", "false").lower() in ("1", "true", "yes"),
        )

        # Observability
        observability_config = ObservabilityConfig(
            prometheus_enabled=os.getenv("ORACLE_PROMETHEUS_ENABLED", "true").lower() in ("1", "true", "yes"),
            tracing_enabled=os.getenv("ORACLE_TRACING_ENABLED", "true").lower() in ("1", "true", "yes"),
            otel_endpoint=os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT") or os.getenv("ORACLE_OTEL_ENDPOINT"),
            sample_rate=float(os.getenv("ORACLE_TRACE_SAMPLE_RATE", "1.0")),
        )

        # Ingress
        ingress_config = IngressConfig(
            host=os.getenv("ORACLE_HOST", "0.0.0.0"),
            port=int(os.getenv("ORACLE_PORT", "8000")),
        )

        # Tenancy
        tenancy_config = TenancyConfig(
            default_tenant_id=os.getenv("ORACLE_DEFAULT_TENANT", "default"),
            enforce_multi_tenancy=os.getenv("ORACLE_ENFORCE_MULTI_TENANCY", "true").lower() in ("1", "true", "yes"),
        )

        # Release
        release_config = OracleReleaseConfig.from_env()

        return cls(
            environment=env,
            database=db_config,
            redis=redis_config,
            webhook=webhook_config,
            worker=worker_config,
            security=security_config,
            observability=observability_config,
            ingress=ingress_config,
            tenancy=tenancy_config,
            release=release_config,
        )

    def validate_configuration(self) -> Tuple[bool, List[str]]:
        """
        Validate configuration.
        In 'production', missing required configurations cause a fail-closed failure.
        """
        errors: List[str] = []

        if self.environment == "production":
            # 1. Database in production MUST be PostgreSQL with valid URL
            if self.database.backend != "postgres":
                errors.append("Production environment requires PostgreSQL database backend (sqlite is not permitted in production).")
            if not self.database.url:
                errors.append("Production environment requires explicit DATABASE_URL / ORACLE_DATABASE_URL.")

            # 2. Webhook secret is required in production
            if not self.webhook.secret_token:
                errors.append("Production environment requires ORACLE_WEBHOOK_SECRET to enforce HMAC integrity.")

            # 3. HTTPS enforcement
            if not self.security.require_https:
                errors.append("Production environment requires ORACLE_REQUIRE_HTTPS=true.")

        # Common validations
        if self.webhook.max_drift_seconds <= 0:
            errors.append("Webhook max_drift_seconds must be positive.")
        if self.webhook.max_payload_bytes <= 0:
            errors.append("Webhook max_payload_bytes must be positive.")
        if self.worker.lease_duration_seconds <= 0:
            errors.append("Worker lease_duration_seconds must be positive.")

        is_valid = len(errors) == 0
        return is_valid, errors

    def to_redacted_dict(self) -> Dict[str, Any]:
        """Produce dictionary with all sensitive tokens and credentials redacted."""
        raw = self.model_dump()

        # Redact database URL credentials
        if raw.get("database", {}).get("url"):
            url = raw["database"]["url"]
            if "@" in url:
                prefix = url.split("@")[1]
                scheme = url.split("://")[0]
                raw["database"]["url"] = f"{scheme}://***REDACTED***@{prefix}"

        # Redact webhook secret
        if raw.get("webhook", {}).get("secret_token"):
            raw["webhook"]["secret_token"] = "***REDACTED***"

        return raw

