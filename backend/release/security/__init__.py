"""
ORACLE Security Intelligence Subsystem (Brick 4.7)

Integrates:
1. SecretStore and SupplyChainSecurityAuditor (Brick 4.6)
2. Canonical Security Domain Models (models.py)
3. Multi-Scanner Finding Normalizer (normalizer.py)
4. Dependency Intelligence Engine (dependency.py)
5. Reachability Intelligence Engine (reachability.py)
6. Exploitability Assessment Engine (exploitability.py)
7. Cross-System Security Correlator (correlation.py)
8. Security Contradiction Engine (contradictions.py)
9. Remediation Intelligence Engine (remediation.py)
10. Security Policy Engine (policy.py)
11. Security Decision Engine (decision.py)
12. Closed-Loop Remediation Verification Engine (verification.py)
13. Asynchronous DAG Security Investigation Engine (investigation.py)
14. Guardrailed Advisory LLM Boundary (advisory.py)
15. Unified Application Facade (api.py)
"""

from backend.release.security.secrets import (
    SecretStore,
    EnvironmentSecretStore,
    KubernetesSecretStore,
    InMemorySecretStore,
    mask_token,
    redact_sensitive_payload,
)
from backend.release.security.supply_chain import (
    SecurityFinding as SupplyChainFinding,
    SupplyChainAuditReport,
    SupplyChainSecurityAuditor,
)
from backend.release.security.models import (
    SecurityCategory,
    SecuritySeverity,
    FindingStatus,
    SecurityFinding,
    Vulnerability,
    DependencyRelationType,
    DependencyScope,
    DependencyRelationship,
    AffectedDependency,
    ReachabilityStatus,
    ReachabilityAssessment,
    ExploitVector,
    ExploitAvailability,
    ExternalExposure,
    AuthRequirement,
    CompensatingControlType,
    CompensatingControl,
    ExploitabilityLevel,
    ExploitabilityAssessment,
    RemediationType,
    SemverImpact,
    RemediationCandidate,
    RemediationCompatibility,
    ContradictionStatus,
    SecurityContradictionRecord,
    SecurityPolicyRule,
    SecurityDecisionOutcome,
    SecurityDecision,
    SecurityVerificationStatus,
    SecurityVerification,
    SecurityInvestigation,
    # Brick 4.8 Models
    DeploymentEnvironment,
    NetworkExposure,
    BuildArtifact,
    Deployment,
    RuntimeService,
    SecurityImpactLevel,
    BusinessImpactLevel,
    ImpactChainNode,
    ImpactChainEdge,
    ImpactChain,
    SecurityImpactAssessment,
    SecurityImpactCluster,
    SecurityReleaseAssessment,
)
from backend.release.security.normalizer import (
    SecurityFindingNormalizer,
    FindingNormalizationError,
)
from backend.release.security.dependency import (
    DependencyIntelligenceEngine,
    VersionComparisonHelper,
)
from backend.release.security.reachability import (
    ReachabilityIntelligenceEngine,
)
from backend.release.security.exploitability import (
    ExploitabilityAssessmentEngine,
)
from backend.release.security.correlation import (
    CrossSystemSecurityCorrelator,
    SecurityCorrelationCluster,
    SecurityCorrelationResult,
)
from backend.release.security.contradictions import (
    SecurityContradictionEngine,
)
from backend.release.security.remediation import (
    RemediationIntelligenceEngine,
)
from backend.release.security.policy import (
    SecurityPolicyEngine,
    PolicyEvaluationResult,
)
from backend.release.security.decision import (
    SecurityDecisionEngine,
)
from backend.release.security.verification import (
    SecurityVerificationEngine,
)
from backend.release.security.investigation import (
    SecurityInvestigationEngine,
)
from backend.release.security.advisory import (
    SecurityAdvisoryExplainer,
    SecuritySovereigntyViolation,
    AdvisoryExplanation,
)
from backend.release.security.exposure import (
    RuntimeExposureEngine,
    RuntimeExposureAssessment,
)
from backend.release.security.business_impact import (
    BusinessImpactEngine,
    BusinessImpactAssessment,
)
from backend.release.security.impact import (
    SecurityImpactEngine,
)
from backend.release.security.clustering import (
    SecurityClusteringEngine,
)
from backend.release.security.api import (
    SecurityIntelligenceAPI,
)

__all__ = [
    # Brick 4.6
    "SecretStore",
    "EnvironmentSecretStore",
    "KubernetesSecretStore",
    "InMemorySecretStore",
    "mask_token",
    "redact_sensitive_payload",
    "SupplyChainFinding",
    "SupplyChainAuditReport",
    "SupplyChainSecurityAuditor",

    # Brick 4.7 Models
    "SecurityCategory",
    "SecuritySeverity",
    "FindingStatus",
    "SecurityFinding",
    "Vulnerability",
    "DependencyRelationType",
    "DependencyScope",
    "DependencyRelationship",
    "AffectedDependency",
    "ReachabilityStatus",
    "ReachabilityAssessment",
    "ExploitVector",
    "ExploitAvailability",
    "ExternalExposure",
    "AuthRequirement",
    "CompensatingControlType",
    "CompensatingControl",
    "ExploitabilityLevel",
    "ExploitabilityAssessment",
    "RemediationType",
    "SemverImpact",
    "RemediationCandidate",
    "RemediationCompatibility",
    "ContradictionStatus",
    "SecurityContradictionRecord",
    "SecurityPolicyRule",
    "SecurityDecisionOutcome",
    "SecurityDecision",
    "SecurityVerificationStatus",
    "SecurityVerification",
    "SecurityInvestigation",

    # Brick 4.7 Engines & APIs
    "SecurityFindingNormalizer",
    "FindingNormalizationError",
    "DependencyIntelligenceEngine",
    "VersionComparisonHelper",
    "ReachabilityIntelligenceEngine",
    "ExploitabilityAssessmentEngine",
    "CrossSystemSecurityCorrelator",
    "SecurityCorrelationCluster",
    "SecurityCorrelationResult",
    "SecurityContradictionEngine",
    "RemediationIntelligenceEngine",
    "SecurityPolicyEngine",
    "PolicyEvaluationResult",
    "SecurityDecisionEngine",
    "SecurityVerificationEngine",
    "SecurityInvestigationEngine",
    "SecurityAdvisoryExplainer",
    "SecuritySovereigntyViolation",
    "AdvisoryExplanation",
    "SecurityIntelligenceAPI",

    # Brick 4.8 Models & Engines
    "DeploymentEnvironment",
    "NetworkExposure",
    "BuildArtifact",
    "Deployment",
    "RuntimeService",
    "SecurityImpactLevel",
    "BusinessImpactLevel",
    "ImpactChainNode",
    "ImpactChainEdge",
    "ImpactChain",
    "SecurityImpactAssessment",
    "SecurityImpactCluster",
    "SecurityReleaseAssessment",
    "RuntimeExposureEngine",
    "RuntimeExposureAssessment",
    "BusinessImpactEngine",
    "BusinessImpactAssessment",
    "SecurityImpactEngine",
    "SecurityClusteringEngine",
]
