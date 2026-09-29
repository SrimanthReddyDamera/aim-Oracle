"""
ORACLE Enterprise Connectivity Subsystem (Brick 4.1)

Production network connectors, credential vault, secret scrubbing, and resilience primitives:
- GitHubReleaseProvider
- JiraWorkManagementProvider
- GitHubActionsCICDProvider
- SemgrepSecurityProvider
- TrivySecurityProvider
- EnterpriseReleaseDataProvider
- CredentialProvider, EnvCredentialProvider, InMemoryCredentialVault, SecretRedactor
- CircuitBreaker, ResilientHttpClient, Provider Network Exceptions
"""

from backend.release.connectivity.resilience import (
    CircuitBreaker,
    CircuitBreakerOpenError,
    CircuitState,
    ProviderAuthenticationError,
    ProviderNetworkError,
    ProviderOutageError,
    ProviderRateLimitError,
    ProviderTimeoutError,
    ResilientHttpClient,
    scrub_secrets,
)
from backend.release.connectivity.credentials import (
    CredentialProvider,
    EnvCredentialProvider,
    GLOBAL_REDACTOR,
    InMemoryCredentialVault,
    SecretRedactor,
)
from backend.release.connectivity.github import GitHubReleaseProvider
from backend.release.connectivity.jira import JiraWorkManagementProvider
from backend.release.connectivity.github_actions import GitHubActionsCICDProvider
from backend.release.connectivity.security import (
    SemgrepSecurityProvider,
    TrivySecurityProvider,
)
from backend.release.connectivity.composite import EnterpriseReleaseDataProvider
from backend.release.connectivity.telemetry import (
    InvestigationTelemetryLedger,
    ProviderOperationTelemetry,
)

__all__ = [
    "CircuitBreaker",
    "CircuitState",
    "CircuitBreakerOpenError",
    "ProviderNetworkError",
    "ProviderAuthenticationError",
    "ProviderRateLimitError",
    "ProviderTimeoutError",
    "ProviderOutageError",
    "ResilientHttpClient",
    "scrub_secrets",
    "CredentialProvider",
    "EnvCredentialProvider",
    "InMemoryCredentialVault",
    "SecretRedactor",
    "GLOBAL_REDACTOR",
    "GitHubReleaseProvider",
    "JiraWorkManagementProvider",
    "GitHubActionsCICDProvider",
    "SemgrepSecurityProvider",
    "TrivySecurityProvider",
    "EnterpriseReleaseDataProvider",
    "InvestigationTelemetryLedger",
    "ProviderOperationTelemetry",
]
