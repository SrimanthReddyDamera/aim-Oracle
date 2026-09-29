"""
Canonical Security Domain Model for ORACLE Security Intelligence Engine (Brick 4.7)

Defines vendor-neutral, controller-authoritative models for:
1. SecurityFinding (normalized cross-scanner finding)
2. Vulnerability (catalog vulnerability record)
3. AffectedDependency & DependencyRelationship (direct/transitive dependency reasoning)
4. ReachabilityAssessment (call-graph and route execution paths)
5. ExploitabilityAssessment (context-aware environmental risk evaluation)
6. SecurityControl & CompensatingControl (active defensive mitigations)
7. RemediationCandidate & RemediationCompatibility (compatibility-checked remediations)
8. SecurityContradictionRecord (epistemic conflict arbitration)
9. SecurityPolicyRule & SecurityDecision (sovereign controller clearance decisions)
10. SecurityVerification (closed-loop rescan verification against exact artifacts)
11. SecurityInvestigation (aggregate container for security analysis)

Guarantees:
- Strict tenant_id, repository, commit, and artifact_digest binding.
- Zero cross-tenant, cross-repo, or wrong-commit evidence leakage.
"""

from __future__ import annotations

import time
import uuid
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple
from pydantic import BaseModel, Field

from backend.evidence.models import Evidence
from backend.investigation.models import ContradictionRecord, InformationGap
from backend.release.models import (
    GovernedActionProposal,
    GovernedActionStatus,
    GovernedActionType,
    RiskLevel,
)


# -----------------------------------------------------------------------------
# 1. CATEGORIES, SEVERITIES & FINDING STATUS
# -----------------------------------------------------------------------------

class SecurityCategory(str, Enum):
    SAST      = "SAST"
    SCA       = "SCA"
    SECRETS   = "SECRETS"
    DAST      = "DAST"
    CONTAINER = "CONTAINER"
    IAC       = "IAC"


class SecuritySeverity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"


class FindingStatus(str, Enum):
    ACTIVE             = "ACTIVE"
    RESOLVED           = "RESOLVED"
    EXCEPTION_ACCEPTED = "EXCEPTION_ACCEPTED"
    FALSE_POSITIVE     = "FALSE_POSITIVE"
    SUPERSEDED         = "SUPERSEDED"


# -----------------------------------------------------------------------------
# 2. CANONICAL SECURITY FINDING & VULNERABILITY
# -----------------------------------------------------------------------------

class Vulnerability(BaseModel):
    """Catalog-level vulnerability definition (CVE / GHSA / OSV)."""
    cve: str = Field(description="Vulnerability identifier e.g. CVE-2023-32681")
    cwe: Optional[str] = None
    cvss_v3: Optional[float] = None
    title: str = ""
    description: str = ""
    advisory_url: Optional[str] = None
    published_date: Optional[str] = None
    epss_score: Optional[float] = None  # Exploit Prediction Scoring System
    known_exploited: bool = False       # CISA KEV presence


class SecurityFinding(BaseModel):
    """
    Canonical vendor-neutral security finding.
    Preserves scanner provenance while strictly binding to repository, commit,
    tenant, and artifact digest.
    """
    finding_id: str = Field(description="Unique finding identifier (e.g. SEC-001 or SNYK-PYTHON-REQUESTS-123)")
    scanner: str = Field(description="Scanner origin e.g. semgrep, snyk, trivy, dependabot, gitleaks, checkov")
    category: SecurityCategory
    severity: SecuritySeverity
    status: FindingStatus = FindingStatus.ACTIVE
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    tenant_id: str = Field(default="default", description="Tenant boundary isolation key")
    repository: str = Field(description="Exact repository URI or slug")
    commit: str = Field(description="Exact Git commit hash being analyzed")
    artifact_digest: Optional[str] = Field(default=None, description="Container/Build artifact SHA-256 digest")
    file: Optional[str] = None
    line_range: Optional[Tuple[int, int]] = None
    package: Optional[str] = None
    current_version: Optional[str] = None
    fixed_version: Optional[str] = None
    vulnerable_version_range: Optional[str] = None
    cve: Optional[str] = None
    cwe: Optional[str] = None
    cvss: Optional[float] = None
    description: str = ""
    remediation_guidance: str = ""
    vulnerable_functions: List[str] = Field(default_factory=list)
    is_exploitable_in_context: bool = True
    is_reachable: bool = True
    first_seen: str = Field(default_factory=lambda: "2026-09-09T12:00:00Z")
    last_seen: str = Field(default_factory=lambda: "2026-09-09T12:00:00Z")
    evidence_ids: List[str] = Field(default_factory=list)
    provenance: Dict[str, Any] = Field(default_factory=dict)
    raw_payload: Dict[str, Any] = Field(default_factory=dict)


# -----------------------------------------------------------------------------
# 3. DEPENDENCY INTELLIGENCE MODELS
# -----------------------------------------------------------------------------

class DependencyRelationType(str, Enum):
    DIRECT     = "DIRECT"
    TRANSITIVE = "TRANSITIVE"


class DependencyScope(str, Enum):
    RUNTIME  = "RUNTIME"
    DEV      = "DEV"
    TEST     = "TEST"
    BUILD    = "BUILD"
    OPTIONAL = "OPTIONAL"


class DependencyRelationship(BaseModel):
    """Parent-child relationship in a dependency graph."""
    parent_package: str
    child_package: str
    constraint: str = "*"
    resolved_version: str = ""
    depth: int = 1


class AffectedDependency(BaseModel):
    """
    Deterministic dependency analysis for an affected package.
    Computes direct vs transitive relationship, all graph paths, version ranges,
    and manifest vs lockfile consistency.
    """
    package_name: str
    installed_version: str
    vulnerable_range: str
    fixed_range: Optional[str] = None
    relation_type: DependencyRelationType = DependencyRelationType.DIRECT
    scope: DependencyScope = DependencyScope.RUNTIME
    dependency_paths: List[List[str]] = Field(
        default_factory=list,
        description="All graph paths introducing package e.g. [['app', 'pkgA', 'pkgB', 'pkgC']]"
    )
    manifest_file: Optional[str] = None
    manifest_version: Optional[str] = None
    lockfile_file: Optional[str] = None
    lockfile_version: Optional[str] = None
    manifest_agrees_with_lockfile: bool = True
    applies_to_commit: bool = True


# -----------------------------------------------------------------------------
# 4. REACHABILITY INTELLIGENCE MODELS
# -----------------------------------------------------------------------------

class ReachabilityStatus(str, Enum):
    CONFIRMED_REACHABLE  = "CONFIRMED_REACHABLE"   # Proven route/entrypoint trace to vulnerable symbol
    POTENTIALLY_REACHABLE = "POTENTIALLY_REACHABLE" # Symbol imported/called in module tree, partial trace
    UNREACHABLE          = "UNREACHABLE"          # Dead code, uncalled function, omitted by config
    REACHABILITY_UNKNOWN = "REACHABILITY_UNKNOWN" # No AST/call-graph evidence available


class ReachabilityAssessment(BaseModel):
    """
    Provider-neutral reachability model.
    Traces: External Entry Point -> Application Route -> Code Path -> Vulnerable Symbol -> Affected Dependency.
    """
    target_package: str
    vulnerable_symbol: Optional[str] = None
    status: ReachabilityStatus = ReachabilityStatus.REACHABILITY_UNKNOWN
    entry_point: Optional[str] = Field(default=None, description="External entrypoint e.g. 'POST /api/v1/payments'")
    route: Optional[str] = None
    code_path: List[str] = Field(
        default_factory=list,
        description="Execution trace e.g. ['app.api:handle_checkout', 'services.billing:charge', 'requests:post']"
    )
    rationale: str = ""
    evidence_ids: List[str] = Field(default_factory=list)
    confidence: float = Field(default=0.8, ge=0.0, le=1.0)
    is_lexical_only: bool = Field(default=False, description="Flagged True if only superficial name overlap was found")


# -----------------------------------------------------------------------------
# 5. EXPLOITABILITY & COMPENSATING CONTROLS
# -----------------------------------------------------------------------------

class ExploitVector(str, Enum):
    NETWORK          = "NETWORK"
    ADJACENT_NETWORK = "ADJACENT_NETWORK"
    LOCAL            = "LOCAL"
    PHYSICAL         = "PHYSICAL"


class ExploitAvailability(str, Enum):
    NONE           = "NONE"
    UNPROVEN       = "UNPROVEN"
    POC            = "POC"
    FUNCTIONAL     = "FUNCTIONAL"
    HIGH           = "HIGH"
    WEAPONIZED     = "WEAPONIZED"
    ACTIVE_IN_WILD = "ACTIVE_IN_WILD"


class DeploymentEnvironment(str, Enum):
    PRODUCTION  = "PRODUCTION"
    STAGING     = "STAGING"
    QA          = "QA"
    DEVELOPMENT = "DEVELOPMENT"
    CANARY      = "CANARY"
    DR          = "DR"


class NetworkExposure(str, Enum):
    INTERNET_FACING = "INTERNET_FACING"
    INTERNAL        = "INTERNAL"
    PRIVATE_NETWORK = "PRIVATE_NETWORK"
    UNKNOWN         = "UNKNOWN"
    # Aliases
    INTERNAL_ONLY   = "INTERNAL"
    AIR_GAPPED      = "PRIVATE_NETWORK"


ExternalExposure = NetworkExposure


class AuthRequirement(str, Enum):
    AUTHENTICATED   = "AUTHENTICATED"
    UNAUTHENTICATED = "UNAUTHENTICATED"
    UNKNOWN         = "UNKNOWN"
    NONE            = "NONE"
    SINGLE          = "SINGLE"
    MULTI           = "MULTI"


class CompensatingControlType(str, Enum):
    WAF              = "WAF"
    NETWORK_POLICY   = "NETWORK_POLICY"
    AUTH_MIDDLEWARE  = "AUTH_MIDDLEWARE"
    RATE_LIMITER     = "RATE_LIMITER"
    SANDBOX          = "SANDBOX"
    RUNTIME_GUARD    = "RUNTIME_GUARD"
    VIRTUAL_PATCH    = "VIRTUAL_PATCH"


class CompensatingControl(BaseModel):
    """Active defensive mitigation protecting the target entity."""
    control_id: str = Field(default_factory=lambda: f"ctrl-{uuid.uuid4().hex[:8]}")
    name: str
    control_type: CompensatingControlType
    is_active: bool = True
    target_entities: List[str] = Field(default_factory=list, description="Endpoints, routes, or services guarded")
    verification_evidence_id: Optional[str] = None
    details: Dict[str, Any] = Field(default_factory=dict)


class ExploitabilityLevel(str, Enum):
    CRITICAL   = "CRITICAL"
    HIGH       = "HIGH"
    MEDIUM     = "MEDIUM"
    LOW        = "LOW"
    NEGLIGIBLE = "NEGLIGIBLE"


class ExploitabilityAssessment(BaseModel):
    """
    Environmental exploitability assessment.
    Combines vulnerability metrics with enterprise context and active compensating controls.
    """
    level: ExploitabilityLevel
    score: float = Field(ge=0.0, le=10.0)
    exploit_vector: ExploitVector = ExploitVector.NETWORK
    exploit_availability: ExploitAvailability = ExploitAvailability.UNPROVEN
    external_exposure: ExternalExposure = ExternalExposure.INTERNET_FACING
    auth_requirement: AuthRequirement = AuthRequirement.NONE
    reachability_status: ReachabilityStatus = ReachabilityStatus.REACHABILITY_UNKNOWN
    active_compensating_controls: List[CompensatingControl] = Field(default_factory=list)
    confidence: float = Field(default=0.85, ge=0.0, le=1.0)
    temporal_validity_seconds: float = Field(default=86400.0, description="Freshness TTL")
    rationale: str = ""
    evidence_ids: List[str] = Field(default_factory=list)


# -----------------------------------------------------------------------------
# 6. REMEDIATION INTELLIGENCE
# -----------------------------------------------------------------------------

class RemediationType(str, Enum):
    DIRECT_UPGRADE       = "DIRECT_UPGRADE"
    TRANSITIVE_OVERRIDE  = "TRANSITIVE_OVERRIDE"
    PATCH                = "PATCH"
    COMPENSATING_CONTROL = "COMPENSATING_CONTROL"
    CODE_MODIFICATION    = "CODE_MODIFICATION"
    WORKAROUND           = "WORKAROUND"


class SemverImpact(str, Enum):
    PATCH = "PATCH"
    MINOR = "MINOR"
    MAJOR = "MAJOR"


class RemediationCandidate(BaseModel):
    """Actionable, compatibility-validated remediation recommendation."""
    candidate_id: str = Field(default_factory=lambda: f"rem-{uuid.uuid4().hex[:8]}")
    target_package: str
    current_version: str
    recommended_version: str
    remediation_type: RemediationType = RemediationType.DIRECT_UPGRADE
    semver_impact: SemverImpact = SemverImpact.PATCH
    breaking_change_risk: float = Field(default=0.1, ge=0.0, le=1.0)
    is_compatible: bool = True
    compatibility_details: str = "Compatible with existing dependency constraints"
    transitive_impacts: List[str] = Field(default_factory=list)
    lockfile_diff: Dict[str, str] = Field(default_factory=dict)
    rollback_guidance: str = ""
    evidence_references: List[str] = Field(default_factory=list)


class RemediationCompatibility(BaseModel):
    """Compatibility evaluation results for a candidate update."""
    is_compatible: bool
    conflicting_constraints: List[str] = Field(default_factory=list)
    breaking_changes: List[str] = Field(default_factory=list)
    lockfile_conflicts: List[str] = Field(default_factory=list)


# -----------------------------------------------------------------------------
# 7. CONTRADICTION ENGINE MODELS
# -----------------------------------------------------------------------------

class ContradictionStatus(str, Enum):
    CONFIRMED             = "CONFIRMED"
    CONTRADICTED          = "CONTRADICTED"
    STALE                 = "STALE"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"
    UNKNOWN               = "UNKNOWN"


class SecurityContradictionRecord(BaseModel):
    """Explicit epistemic contradiction record."""
    contradiction_id: str = Field(default_factory=lambda: f"scontra-{uuid.uuid4().hex[:8]}")
    finding_id: str
    conflict_type: str  # SCANNER_MISMATCH, MANIFEST_VS_LOCKFILE, CLAIM_VS_RESCAN, SAST_VS_REACHABILITY, ARTIFACT_VS_HEAD
    source_a: str
    source_b: str
    claim_a: str
    claim_b: str
    evidence_a_id: str
    evidence_b_id: str
    status: ContradictionStatus = ContradictionStatus.CONTRADICTED
    explanation: str

    @property
    def contradiction_type(self) -> str:
        return self.conflict_type


# -----------------------------------------------------------------------------
# 8. SECURITY POLICY & DECISION MODELS
# -----------------------------------------------------------------------------

class SecurityDecisionOutcome(str, Enum):
    SECURITY_CLEAR                  = "SECURITY_CLEAR"
    SECURITY_BLOCKED                = "SECURITY_BLOCKED"
    SECURITY_REQUIRES_REVIEW        = "SECURITY_REQUIRES_REVIEW"
    SECURITY_CONDITIONAL            = "SECURITY_CONDITIONAL"
    SECURITY_INSUFFICIENT_EVIDENCE  = "SECURITY_INSUFFICIENT_EVIDENCE"
    SECURITY_UNKNOWN                = "SECURITY_UNKNOWN"
    SECURITY_RECONCILIATION_REQUIRED = "SECURITY_RECONCILIATION_REQUIRED"


class SecurityPolicyRule(BaseModel):
    """Deterministic security policy rule."""
    rule_id: str
    name: str
    condition_description: str
    severity_threshold: SecuritySeverity
    require_reachability: bool = True
    require_fresh_rescan: bool = True
    action_outcome: SecurityDecisionOutcome


class SecurityDecision(BaseModel):
    """
    Sovereign Controller Security Clearance Decision.
    Derives purely from deterministic policy rules and verified evidence.
    """
    decision_id: str = Field(default_factory=lambda: f"secdec-{uuid.uuid4().hex[:8]}")
    tenant_id: str = "default"
    repository: str
    commit: str
    artifact_digest: Optional[str] = None
    outcome: SecurityDecisionOutcome
    risk_level: RiskLevel
    confidence: float = Field(ge=0.0, le=1.0)
    deterministic_reason: str
    blocking_factors: List[str] = Field(default_factory=list)
    verified_factors: List[str] = Field(default_factory=list)
    recommendations: List[RemediationCandidate] = Field(default_factory=list)
    governed_actions: List[GovernedActionProposal] = Field(default_factory=list)
    evidence_references: List[str] = Field(default_factory=list)
    policy_rules_invoked: List[str] = Field(default_factory=list)
    contradictions: List[SecurityContradictionRecord] = Field(default_factory=list)
    unresolved_gaps: List[str] = Field(default_factory=list)
    decision_lineage: List[Dict[str, Any]] = Field(default_factory=list)
    timestamp: str = Field(default_factory=lambda: "2026-09-09T12:00:00Z")


# -----------------------------------------------------------------------------
# 9. CLOSED-LOOP VERIFICATION
# -----------------------------------------------------------------------------

class SecurityVerificationStatus(str, Enum):
    VERIFIED_RESOLVED  = "VERIFIED_RESOLVED"  # Fresh scan on exact fixed commit proves clean
    STILL_VULNERABLE   = "STILL_VULNERABLE"   # Rescan still detects vulnerability
    UNVERIFIED         = "UNVERIFIED"         # No fresh rescan has executed
    CONTRADICTED       = "CONTRADICTED"       # Conflicting rescan results
    STALE_VERIFICATION = "STALE_VERIFICATION" # Rescan belongs to older commit


class SecurityVerification(BaseModel):
    """Authoritative record of closed-loop verification."""
    verification_id: str = Field(default_factory=lambda: f"secver-{uuid.uuid4().hex[:8]}")
    finding_id: str
    tenant_id: str = "default"
    rescan_commit: str
    rescan_artifact_digest: Optional[str] = None
    rescan_evidence_ids: List[str] = Field(default_factory=list)
    status: SecurityVerificationStatus
    verified_at: str = Field(default_factory=lambda: "2026-09-09T12:00:00Z")
    verifier_source: str = "security_rescan"
    notes: str = ""

    @property
    def is_verified(self) -> bool:
        return self.status == SecurityVerificationStatus.VERIFIED_RESOLVED

    @property
    def failure_reason(self) -> str:
        return self.notes


# -----------------------------------------------------------------------------
# 10. EXACT ARTIFACT, DEPLOYMENT & RUNTIME SERVICE MODELS (Brick 4.8)
# -----------------------------------------------------------------------------

class BuildArtifact(BaseModel):
    """
    Exact built artifact record (Container image, JAR, wheel, binary).
    Distinguishes: Repository HEAD != Built Artifact != Deployed Artifact != Running Service.
    """
    artifact_id: str = Field(default_factory=lambda: f"art-{uuid.uuid4().hex[:8]}")
    artifact_digest: str = Field(description="Deterministic cryptographic digest e.g. sha256:7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069")
    artifact_name: str = ""
    repository: str
    commit: str
    build_id: str = ""
    built_at: str = Field(default_factory=lambda: "2026-09-09T12:00:00Z")
    tenant_id: str = "default"
    manifest_hash: Optional[str] = None
    dependencies: Dict[str, str] = Field(default_factory=dict, description="Resolved package -> version mappings in artifact")
    is_vulnerable: bool = False
    vulnerability_details: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class Deployment(BaseModel):
    """
    Exact deployment binding record.
    Represents an immutable deployment event of a specific artifact to a specific environment.
    """
    deployment_id: str = Field(default_factory=lambda: f"dep-{uuid.uuid4().hex[:8]}")
    service_id: str
    environment: DeploymentEnvironment = DeploymentEnvironment.PRODUCTION
    artifact_digest: str
    commit: str
    deployed_at: str = Field(default_factory=lambda: "2026-09-09T12:00:00Z")
    deployed_by: str = "oracle-deployer"
    status: str = "ACTIVE"  # ACTIVE, SUPERSEDED, FAILED, ROLLBACK
    tenant_id: str = "default"
    is_active_in_production: bool = True
    metadata: Dict[str, Any] = Field(default_factory=dict)


class RuntimeService(BaseModel):
    """
    Live running service context.
    Captures network exposure, active compensating controls, and operational criticality.
    """
    service_id: str
    service_name: str
    tenant_id: str = "default"
    environment: DeploymentEnvironment = DeploymentEnvironment.PRODUCTION
    exposure: NetworkExposure = NetworkExposure.UNKNOWN
    auth_required: AuthRequirement = AuthRequirement.UNKNOWN
    entry_points: List[str] = Field(default_factory=list, description="External HTTP routes or RPC methods")
    active_compensating_controls: List[CompensatingControl] = Field(default_factory=list)
    criticality_tier: str = "NORMAL"  # TIER_1, CRITICAL, HIGH, NORMAL, LOW
    is_production: bool = True
    active_deployment_id: Optional[str] = None
    active_artifact_digest: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


# -----------------------------------------------------------------------------
# 11. SECURITY IMPACT & BUSINESS IMPACT MODELS (Brick 4.8)
# -----------------------------------------------------------------------------

class SecurityImpactLevel(str, Enum):
    CRITICAL_IMPACT   = "CRITICAL_IMPACT"
    HIGH_IMPACT       = "HIGH_IMPACT"
    MODERATE_IMPACT   = "MODERATE_IMPACT"
    LOW_IMPACT        = "LOW_IMPACT"
    NEGLIGIBLE_IMPACT = "NEGLIGIBLE_IMPACT"
    UNKNOWN_IMPACT    = "UNKNOWN_IMPACT"


class BusinessImpactLevel(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MODERATE = "MODERATE"
    LOW      = "LOW"
    UNKNOWN  = "UNKNOWN"


# -----------------------------------------------------------------------------
# 12. ATTACK-PATH & IMPACT CHAIN MODELS (Brick 4.8)
# -----------------------------------------------------------------------------

class ImpactChainNode(BaseModel):
    node_id: str
    node_type: str  # CVE, PACKAGE, DEPENDENCY_PATH, VULNERABLE_FUNCTION, ROUTE, RUNTIME_SERVICE, DEPLOYMENT, EXPOSURE, RELEASE
    label: str
    properties: Dict[str, Any] = Field(default_factory=dict)


class ImpactChainEdge(BaseModel):
    from_node_id: str
    to_node_id: str
    relationship: str  # AFFECTS, DEPENDS_ON, REACHABLE_FROM, BUILT_AS, DEPLOYED_AS, RUNS_AS, EXPOSED_BY, REPRESENTS
    provenance: str = "deterministic_analysis"
    confidence: float = 1.0


class ImpactChain(BaseModel):
    """
    Evidence-backed, structured attack-path and impact chain.
    Traces: CVE -> vulnerable package -> dependency path -> vulnerable function -> HTTP route -> runtime service -> production deployment -> internet exposure -> release candidate.
    """
    finding_id: str
    nodes: List[ImpactChainNode] = Field(default_factory=list)
    edges: List[ImpactChainEdge] = Field(default_factory=list)
    summary: str = ""


# -----------------------------------------------------------------------------
# 13. SECURITY IMPACT ASSESSMENT & CLUSTERING (Brick 4.8)
# -----------------------------------------------------------------------------

class SecurityImpactAssessment(BaseModel):
    """
    Deterministic multi-dimensional assessment answering:
    'Does this security finding actually affect this exact release/deployment?'
    """
    assessment_id: str = Field(default_factory=lambda: f"secimp-{uuid.uuid4().hex[:8]}")
    finding_id: str
    tenant_id: str = "default"
    repository: str
    commit: str
    artifact_digest: Optional[str] = None
    deployment_id: Optional[str] = None
    service_id: Optional[str] = None
    environment: DeploymentEnvironment = DeploymentEnvironment.PRODUCTION

    # Multi-dimensional evaluation outcomes
    impact_level: SecurityImpactLevel
    business_impact: BusinessImpactLevel
    vulnerability_severity: SecuritySeverity
    cvss: Optional[float] = None
    epss: Optional[float] = None
    known_exploited: bool = False

    reachability_status: ReachabilityStatus = ReachabilityStatus.REACHABILITY_UNKNOWN
    network_exposure: NetworkExposure = NetworkExposure.UNKNOWN
    auth_requirement: AuthRequirement = AuthRequirement.UNKNOWN

    is_runtime_dependency: bool = True
    is_transitive: bool = False
    dependency_scope: DependencyScope = DependencyScope.RUNTIME

    artifact_is_vulnerable: bool = True
    artifact_drift_detected: bool = False

    impact_chain: Optional[ImpactChain] = None
    rationale: str = ""
    evidence_references: List[str] = Field(default_factory=list)
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    assessed_at: str = Field(default_factory=lambda: "2026-09-09T12:00:00Z")


class SecurityImpactCluster(BaseModel):
    """
    Grouped security findings across scanners sharing root cause, package, or remediation.
    Preserves finding-level provenance.
    """
    cluster_id: str = Field(default_factory=lambda: f"cluster-{uuid.uuid4().hex[:8]}")
    root_cve: Optional[str] = None
    affected_package: Optional[str] = None
    affected_service: Optional[str] = None
    finding_ids: List[str] = Field(default_factory=list)
    findings: List[SecurityFinding] = Field(default_factory=list)
    cluster_impact_level: SecurityImpactLevel = SecurityImpactLevel.MODERATE_IMPACT
    common_remediation: Optional[RemediationCandidate] = None
    is_independent: bool = False
    provenance: Dict[str, Any] = Field(default_factory=dict)


class SecurityReleaseAssessment(BaseModel):
    """
    Release-correlated security assessment answering:
    'Are there any security findings that materially block this exact release candidate?'
    """
    release_id: str
    tenant_id: str = "default"
    repository: str
    commit: str
    artifact_digest: Optional[str] = None
    deployment_id: Optional[str] = None
    service_id: Optional[str] = None
    environment: DeploymentEnvironment = DeploymentEnvironment.PRODUCTION
    security_decision: SecurityDecision
    impact_assessments: List[SecurityImpactAssessment] = Field(default_factory=list)
    clusters: List[SecurityImpactCluster] = Field(default_factory=list)
    contradictions: List[SecurityContradictionRecord] = Field(default_factory=list)
    artifact_drift_detected: bool = False
    is_release_blocked: bool = False
    blocking_reasons: List[str] = Field(default_factory=list)
    clear_reasons: List[str] = Field(default_factory=list)
    created_at: str = Field(default_factory=lambda: "2026-09-09T12:00:00Z")

    @property
    def outcome(self) -> SecurityDecisionOutcome:
        return self.security_decision.outcome if self.security_decision else SecurityDecisionOutcome.SECURITY_CLEAR

    @property
    def blocks_release(self) -> bool:
        return self.is_release_blocked


# -----------------------------------------------------------------------------
# 14. SECURITY INVESTIGATION AGGREGATE (Brick 4.8 Extended)
# -----------------------------------------------------------------------------

class SecurityInvestigation(BaseModel):
    """
    Authoritative aggregate container for a security investigation.
    Fully integrated with artifacts, deployments, runtime services, impact assessments,
    finding clusters, and release correlation.
    """
    investigation_id: str = Field(default_factory=lambda: f"secinv-{uuid.uuid4().hex[:8]}")
    tenant_id: str = "default"
    repository: str
    commit: str
    artifact_digest: Optional[str] = None
    deployment_id: Optional[str] = None
    service_id: Optional[str] = None
    environment: DeploymentEnvironment = DeploymentEnvironment.PRODUCTION

    findings: List[SecurityFinding] = Field(default_factory=list)
    dependencies: Dict[str, AffectedDependency] = Field(default_factory=dict)
    reachability: Dict[str, ReachabilityAssessment] = Field(default_factory=dict)
    exploitability: Dict[str, ExploitabilityAssessment] = Field(default_factory=dict)
    impact_assessments: Dict[str, SecurityImpactAssessment] = Field(default_factory=dict)
    clusters: List[SecurityImpactCluster] = Field(default_factory=list)
    contradictions: List[SecurityContradictionRecord] = Field(default_factory=list)
    verifications: List[SecurityVerification] = Field(default_factory=list)
    artifacts: Dict[str, BuildArtifact] = Field(default_factory=dict)
    deployments: Dict[str, Deployment] = Field(default_factory=dict)
    services: Dict[str, RuntimeService] = Field(default_factory=dict)
    release_assessment: Optional[SecurityReleaseAssessment] = None
    decision: Optional[SecurityDecision] = None

    admitted_evidence: List[Evidence] = Field(default_factory=list)
    rejected_evidence: List[Any] = Field(default_factory=list)
    gaps: List[InformationGap] = Field(default_factory=list)
    telemetry: Dict[str, Any] = Field(default_factory=dict)
    created_at: str = Field(default_factory=lambda: "2026-09-09T12:00:00Z")
    updated_at: str = Field(default_factory=lambda: "2026-09-09T12:00:00Z")

    @property
    def admitted_findings(self) -> List[str]:
        return [f.finding_id for f in self.findings]

