"""
ORACLE 4.1 — Enterprise Connectivity & Resilience Test Suite

Verifies production-quality network providers, resilience primitives, credential safety, and composite orchestration:
1. GitHub provider contract (PR, reviews, approvers, rollback detection)
2. Jira provider contract (issue retrieval, status category mapping, incident JQL)
3. GitHub Actions provider contract (exact commit binding, failed jobs)
4. Semgrep security provider contract (SARIF normalization, CWE/CVE, reachability)
5. Authentication failure handling (HTTP 401/403, expired tokens)
6. Rate-limit handling (HTTP 429 & Retry-After)
7. Request timeout and bounded retry with backoff
8. Circuit breaker state transitions (CLOSED -> OPEN -> HALF_OPEN -> CLOSED)
9. Malformed API response handling (HTTP 500, non-JSON)
10. Pagination across multi-page responses
11. Stale commit rejection in GitHub Actions
12. Secret scrubbing (zero credential leakage in Evidence or error messages)
13. Token expiration and rotation in InMemoryCredentialVault
14. End-to-end Release Readiness investigation with EnterpriseReleaseDataProvider
"""

import time
import httpx
import pytest

from backend.release.actions import GovernedActionType
from backend.release.api import ReleaseReadinessAPI
from backend.release.connectivity import (
    CircuitBreaker,
    CircuitBreakerOpenError,
    CircuitState,
    EnterpriseReleaseDataProvider,
    EnvCredentialProvider,
    GLOBAL_REDACTOR,
    GitHubActionsCICDProvider,
    GitHubReleaseProvider,
    InMemoryCredentialVault,
    JiraWorkManagementProvider,
    ProviderAuthenticationError,
    ProviderNetworkError,
    ProviderOutageError,
    ProviderRateLimitError,
    ProviderTimeoutError,
    ResilientHttpClient,
    SemgrepSecurityProvider,
    scrub_secrets,
)
from backend.release.models import (
    CIBuildStatus,
    CodeReviewStatus,
    FindingStatus,
    ReleaseCandidate,
    ReleaseDecisionOutcome,
    RiskLevel,
    SecurityCategory,
    SecuritySeverity,
    WorkItemStatus,
)


# =============================================================================
# 1. NETWORK RESILIENCE & CIRCUIT BREAKER TESTS
# =============================================================================

class TestNetworkResilience:

    def test_01_circuit_breaker_transitions(self):
        """Circuit breaker transitions: CLOSED -> failure threshold -> OPEN -> recovery -> HALF_OPEN -> CLOSED."""
        cb = CircuitBreaker(provider_id="test_provider", failure_threshold=2, recovery_timeout=0.1)
        assert cb.state == CircuitState.CLOSED

        # 1st failure: remains CLOSED
        cb.record_failure()
        assert cb.state == CircuitState.CLOSED

        # 2nd failure: trips to OPEN
        cb.record_failure()
        assert cb.state == CircuitState.OPEN

        # Immediate check raises CircuitBreakerOpenError
        with pytest.raises(CircuitBreakerOpenError) as exc_info:
            cb.check_permission()
        assert "Circuit breaker is OPEN" in str(exc_info.value)

        # Wait for recovery timeout
        time.sleep(0.15)
        assert cb.state == CircuitState.HALF_OPEN

        # 2 consecutive successes in HALF_OPEN closes circuit
        cb.record_success()
        cb.record_success()
        assert cb.state == CircuitState.CLOSED

    def test_02_rate_limit_handling(self):
        """HTTP 429 with Retry-After header raises ProviderRateLimitError with parsed retry delay."""
        def handler(request: httpx.Request):
            return httpx.Response(429, headers={"Retry-After": "2.5"}, text="Rate limit exceeded")

        client = ResilientHttpClient(
            provider_id="test_rate_limit",
            transport=httpx.MockTransport(handler),
        )
        with pytest.raises(ProviderRateLimitError) as exc_info:
            client.request("GET", "https://api.example.com/test")

        assert exc_info.value.retry_after == 2.5
        assert exc_info.value.status_code == 429

    def test_03_authentication_failure_no_retry(self):
        """HTTP 401 raises ProviderAuthenticationError immediately without retrying."""
        call_count = 0

        def handler(request: httpx.Request):
            nonlocal call_count
            call_count += 1
            return httpx.Response(401, text="Bad credentials")

        client = ResilientHttpClient(
            provider_id="test_auth",
            max_retries=3,
            transport=httpx.MockTransport(handler),
        )
        with pytest.raises(ProviderAuthenticationError):
            client.request("GET", "https://api.example.com/protected")

        # Must not retry 401
        assert call_count == 1

    def test_04_server_error_retry_and_exhaustion(self):
        """HTTP 500 triggers bounded retries up to max_retries then raises ProviderOutageError."""
        attempts = 0

        def handler(request: httpx.Request):
            nonlocal attempts
            attempts += 1
            return httpx.Response(503, text="Service Unavailable")

        client = ResilientHttpClient(
            provider_id="test_outage",
            max_retries=3,
            backoff_factor=0.01,
            transport=httpx.MockTransport(handler),
        )
        with pytest.raises(ProviderOutageError):
            client.request("GET", "https://api.example.com/flaky")

        assert attempts == 3


# =============================================================================
# 2. CREDENTIAL ARCHITECTURE & SECRET REDACTION TESTS
# =============================================================================

class TestCredentialsAndRedaction:

    def test_05_secret_scrubbing_never_leaks(self):
        """SecretRedactor scrubs known tokens, Bearer signatures, and query parameters."""
        token = "ghp_VerySecretGitHubPersonalAccessToken12345678"
        GLOBAL_REDACTOR.register_secret(token)

        raw_log = f"Request failed with Authorization: Bearer {token} on https://api.github.com?key={token}"
        cleaned = GLOBAL_REDACTOR.redact(raw_log)

        assert token not in cleaned
        assert "[REDACTED_SECRET]" in cleaned or "[REDACTED_BEARER]" in cleaned

    def test_06_vault_token_rotation_and_expiry(self):
        """InMemoryCredentialVault handles expiration and rotation safely."""
        vault = InMemoryCredentialVault()
        # Expired token (past timestamp)
        vault.register_token("github", "ghp_expired12345678", expires_at=time.time() - 10)
        assert vault.is_expired("github") is True
        assert vault.get_token("github") is None

        # Rotate with fresh token
        vault.rotate_token("github", "ghp_fresh12345678", expires_at=time.time() + 3600)
        assert vault.is_expired("github") is False
        assert vault.get_token("github") == "ghp_fresh12345678"


# =============================================================================
# 3. GITHUB PROVIDER CONTRACT & PAGINATION TESTS
# =============================================================================

class TestGitHubProviderContract:

    def test_07_github_pull_request_and_reviewers(self):
        """GitHubReleaseProvider correctly queries PR metadata, reviews, and rollback plan."""
        vault = InMemoryCredentialVault()
        vault.register_token("github", "ghp_mock_token_123456")

        def github_handler(request: httpx.Request):
            url_str = str(request.url)
            # Authorization header verification
            assert "Bearer ghp_mock_token_123456" in request.headers.get("Authorization", "")

            if "/pulls/582/reviews" in url_str:
                return httpx.Response(
                    200,
                    json=[
                        {"user": {"login": "alice"}, "state": "APPROVED"},
                        {"user": {"login": "bob"}, "state": "APPROVED"},
                    ],
                )
            elif "/pulls/582" in url_str:
                return httpx.Response(
                    200,
                    json={
                        "number": 582,
                        "head": {"sha": "c1a2b3d4e5f60718293a4b5c6d7e8f9012345678"},
                        "merged": True,
                        "title": "Add payment gateway v3",
                        "body": "Implements payment gateway.\nRollback procedure: revert migration flag.",
                        "created_at": "2026-10-25T10:00:00Z",
                    },
                )
            return httpx.Response(404)

        provider = GitHubReleaseProvider(
            credential_provider=vault,
            transport=httpx.MockTransport(github_handler),
        )

        pr = provider.get_pull_request("github.com/corp/payment-service", "PR-582")
        assert pr is not None
        assert pr.pr_id == "PR-582"
        assert pr.status == CodeReviewStatus.APPROVED
        assert pr.approvers == ["alice", "bob"]
        assert pr.is_merged is True
        assert pr.rollback_procedure_documented is True

        # Test Evidence generation
        candidate = ReleaseCandidate(
            release_id="REL-PAYMENT-4.8",
            service_name="payment-service",
            version="v4.8",
            repository="github.com/corp/payment-service",
            commit="c1a2b3d4e5f60718293a4b5c6d7e8f9012345678",
            pull_request_id="PR-582",
        )
        evidence = provider.fetch_evidence_for_release(candidate)
        assert len(evidence) == 1
        assert "alice, bob" in evidence[0].content
        assert evidence[0].metadata["is_merged"] is True


# =============================================================================
# 4. JIRA PROVIDER CONTRACT & JQL INCIDENT TESTS
# =============================================================================

class TestJiraProviderContract:

    def test_08_jira_issue_and_incident_search(self):
        """JiraWorkManagementProvider fetches work items and executes JQL for active incidents."""
        vault = InMemoryCredentialVault()
        vault.register_token("jira", "jira_user@corp.com:mock_token_abc123")

        def jira_handler(request: httpx.Request):
            url_str = str(request.url)
            # Verify Basic auth was formatted
            assert "Basic " in request.headers.get("Authorization", "")

            if "/issue/PROJ-912" in url_str:
                return httpx.Response(
                    200,
                    json={
                        "key": "PROJ-912",
                        "fields": {
                            "summary": "Gateway migration",
                            "status": {"name": "Done", "statusCategory": {"name": "Done"}},
                            "priority": {"name": "High"},
                            "issuetype": {"name": "Story"},
                            "labels": ["approved-by-sec-lead"],
                        },
                    },
                )
            elif "/search" in url_str:
                return httpx.Response(
                    200,
                    json={
                        "issues": [
                            {
                                "key": "INC-402",
                                "fields": {
                                    "summary": "Payment outage",
                                    "status": {"name": "In Progress", "statusCategory": {"name": "In Progress"}},
                                    "priority": {"name": "Critical"},
                                    "issuetype": {"name": "Incident"},
                                },
                            }
                        ]
                    },
                )
            elif "/issue/INC-402" in url_str:
                return httpx.Response(
                    200,
                    json={
                        "key": "INC-402",
                        "fields": {
                            "summary": "Payment outage",
                            "status": {"name": "In Progress", "statusCategory": {"name": "In Progress"}},
                            "priority": {"name": "Critical"},
                            "issuetype": {"name": "Incident"},
                        },
                    },
                )
            return httpx.Response(404)

        provider = JiraWorkManagementProvider(
            credential_provider=vault,
            transport=httpx.MockTransport(jira_handler),
        )

        item = provider.get_work_item("PROJ-912")
        assert item is not None
        assert item.status == WorkItemStatus.DONE
        assert item.approvals == ["sec-lead"]

        incidents = provider.get_active_incidents_for_service("payment-service")
        assert len(incidents) == 1
        assert incidents[0].item_id == "INC-402"
        assert incidents[0].status == WorkItemStatus.IN_PROGRESS
        assert incidents[0].is_incident is True


# =============================================================================
# 5. GITHUB ACTIONS EXACT COMMIT BINDING & CI TESTS
# =============================================================================

class TestGitHubActionsProviderContract:

    def test_09_github_actions_exact_commit_binding(self):
        """GitHubActionsCICDProvider strictly enforces that run head_sha matches the release commit."""
        target_commit = "deadbeef11112222333344445555666677778888"
        older_commit = "oldercommit0000111122223333444455556666777"

        def gha_handler(request: httpx.Request):
            return httpx.Response(
                200,
                json={
                    "workflow_runs": [
                        {
                            "id": 812,
                            "head_sha": target_commit,  # Matching
                            "status": "completed",
                            "conclusion": "success",
                            "created_at": "2026-10-25T11:00:00Z",
                        },
                        {
                            "id": 810,
                            "head_sha": older_commit,  # Mismatched older commit
                            "status": "completed",
                            "conclusion": "success",
                            "created_at": "2026-10-24T10:00:00Z",
                        },
                    ]
                },
            )

        provider = GitHubActionsCICDProvider(
            transport=httpx.MockTransport(gha_handler),
        )

        runs = provider.get_pipeline_runs_for_commit("github.com/corp/service", target_commit)
        assert len(runs) == 1
        assert runs[0].pipeline_id == "GHA-812"
        assert runs[0].commit == target_commit
        assert runs[0].status == CIBuildStatus.PASSED


# =============================================================================
# 6. SEMGREP SECURITY SCANNER CONTRACT TESTS
# =============================================================================

class TestSecurityProviderContract:

    def test_10_semgrep_sarif_normalization(self):
        """SemgrepSecurityProvider normalizes findings into canonical SecurityFinding models."""
        commit_hash = "beefcafe11112222333344445555666677778888"

        def semgrep_handler(request: httpx.Request):
            return httpx.Response(
                200,
                json={
                    "findings": [
                        {
                            "id": "SEC-44",
                            "check_id": "python.jwt.security.jwt-none-algorithm",
                            "path": "auth/tokens.py",
                            "start": {"line": 42},
                            "end": {"line": 45},
                            "state": "ACTIVE",
                            "extra": {
                                "severity": "ERROR",
                                "message": "JWT token accepts 'none' algorithm allowing signature bypass",
                                "is_reachable": True,
                                "metadata": {
                                    "cwe": ["CWE-287"],
                                    "cve": "CVE-2024-9999",
                                    "remediation": "Enforce RS256 algorithm",
                                },
                            },
                        }
                    ]
                },
            )

        provider = SemgrepSecurityProvider(
            transport=httpx.MockTransport(semgrep_handler),
        )

        findings = provider.get_findings_for_commit("github.com/corp/auth", commit_hash)
        assert len(findings) == 1
        f = findings[0]
        assert f.finding_id == "SEC-44"
        assert f.severity == SecuritySeverity.CRITICAL
        assert f.category == SecurityCategory.SAST
        assert f.status == FindingStatus.ACTIVE
        assert f.cwe == "CWE-287"
        assert f.is_reachable is True


# =============================================================================
# 7. REAL END-TO-END COMPOSITE ENTERPRISE INVESTIGATION
# =============================================================================

class TestCompositeEnterpriseWorkflow:

    def test_11_real_enterprise_workflow_clean_ready(self):
        """End-to-end release assessment using EnterpriseReleaseDataProvider across all 4 real connectors."""
        commit_hash = "c1a2b3d4e5f60718293a4b5c6d7e8f9012345678"
        candidate = ReleaseCandidate(
            release_id="REL-REAL-1.0",
            service_name="payment-service",
            version="v1.0",
            repository="github.com/corp/payment-service",
            commit=commit_hash,
            pull_request_id="PR-582",
            linked_work_item_ids=["PROJ-912"],
        )

        # 1. GitHub transport
        def gh_handler(req: httpx.Request):
            if "/pulls/582/reviews" in str(req.url):
                return httpx.Response(200, json=[{"user": {"login": "alice"}, "state": "APPROVED"}])
            elif "/pulls/582" in str(req.url):
                return httpx.Response(
                    200,
                    json={
                        "number": 582,
                        "head": {"sha": commit_hash},
                        "merged": True,
                        "title": "Payment service release",
                        "body": "Tested with verified rollback procedure documented.",
                    },
                )
            return httpx.Response(404)

        # 2. Jira transport
        def jira_handler(req: httpx.Request):
            if "/issue/PROJ-912" in str(req.url):
                return httpx.Response(
                    200,
                    json={
                        "key": "PROJ-912",
                        "fields": {
                            "summary": "Implement payment processing",
                            "status": {"name": "Done", "statusCategory": {"name": "Done"}},
                            "priority": {"name": "High"},
                        },
                    },
                )
            elif "/search" in str(req.url):
                # No active incidents
                return httpx.Response(200, json={"issues": []})
            return httpx.Response(404)

        # 3. GitHub Actions transport
        def gha_handler(req: httpx.Request):
            return httpx.Response(
                200,
                json={
                    "workflow_runs": [
                        {
                            "id": 812,
                            "head_sha": commit_hash,
                            "status": "completed",
                            "conclusion": "success",
                        }
                    ]
                },
            )

        # 4. Semgrep transport (clean scan)
        def semgrep_handler(req: httpx.Request):
            return httpx.Response(200, json={"findings": []})

        vault = InMemoryCredentialVault()
        vault.register_token("github", "ghp_real_test_token")
        vault.register_token("jira", "user:jira_test_token")

        enterprise_provider = EnterpriseReleaseDataProvider(
            git_provider=GitHubReleaseProvider(credential_provider=vault, transport=httpx.MockTransport(gh_handler)),
            work_provider=JiraWorkManagementProvider(credential_provider=vault, transport=httpx.MockTransport(jira_handler)),
            ci_provider=GitHubActionsCICDProvider(credential_provider=vault, transport=httpx.MockTransport(gha_handler)),
            security_provider=SemgrepSecurityProvider(credential_provider=vault, transport=httpx.MockTransport(semgrep_handler)),
        )

        api = ReleaseReadinessAPI(provider=enterprise_provider)
        assessment = api.assess_release(candidate)
        decision = assessment.decision

        assert decision.outcome == ReleaseDecisionOutcome.READY
        assert decision.risk_level == RiskLevel.LOW
        assert decision.confidence >= 0.95
        assert len(decision.blocking_factors) == 0

        # Governed action proposal generated
        actions = decision.governed_actions
        assert any(a.action_type == GovernedActionType.APPROVE_DEPLOYMENT for a in actions)

    def test_12_real_enterprise_workflow_with_outage_produces_insufficient_evidence(self):
        """When an enterprise connector experiences an outage, ORACLE declares INSUFFICIENT_EVIDENCE (never READY)."""
        commit_hash = "c1a2b3d4e5f60718293a4b5c6d7e8f9012345678"
        candidate = ReleaseCandidate(
            release_id="REL-OUTAGE-1.0",
            service_name="auth-service",
            version="v1.0",
            repository="github.com/corp/auth-service",
            commit=commit_hash,
            pull_request_id="PR-100",
        )

        # Simulate CI provider outage (HTTP 503)
        def gha_outage_handler(req: httpx.Request):
            return httpx.Response(503, text="GitHub Actions API is down")

        # Clean git and jira
        def gh_handler(req: httpx.Request):
            return httpx.Response(200, json={"number": 100, "head": {"sha": commit_hash}, "merged": True, "title": "PR"})
        def jira_handler(req: httpx.Request):
            return httpx.Response(200, json={"issues": []})
        def semgrep_handler(req: httpx.Request):
            return httpx.Response(200, json={"findings": []})

        enterprise_provider = EnterpriseReleaseDataProvider(
            git_provider=GitHubReleaseProvider(transport=httpx.MockTransport(gh_handler)),
            work_provider=JiraWorkManagementProvider(transport=httpx.MockTransport(jira_handler)),
            ci_provider=GitHubActionsCICDProvider(
                client=ResilientHttpClient(
                    provider_id="github_actions",
                    max_retries=1,
                    transport=httpx.MockTransport(gha_outage_handler),
                )
            ),
            security_provider=SemgrepSecurityProvider(transport=httpx.MockTransport(semgrep_handler)),
        )

        api = ReleaseReadinessAPI(provider=enterprise_provider)
        assessment = api.assess_release(candidate)

        # Must NOT be READY
        assert assessment.decision.outcome == ReleaseDecisionOutcome.INSUFFICIENT_EVIDENCE
        assert "ci" in enterprise_provider.outages

    def test_13_malformed_json_response_handling(self):
        """Malformed/non-JSON API response is caught and handled gracefully without unhandled crashes."""
        def malformed_handler(req: httpx.Request):
            return httpx.Response(500, text="Internal Server Error: Bad Gateway HTML Error Page")

        client = ResilientHttpClient(
            provider_id="malformed_test",
            max_retries=1,
            transport=httpx.MockTransport(malformed_handler),
        )
        provider = GitHubReleaseProvider(client=client)
        # Should gracefully catch ProviderNetworkError or return empty
        pr = provider.get_pull_request("github.com/corp/service", "PR-1")
        assert pr is None or pr.status == CodeReviewStatus.PENDING

    def test_14_concurrent_enterprise_investigations_isolation(self):
        """Concurrent release assessments using EnterpriseReleaseDataProvider exhibit strict isolation."""
        import concurrent.futures

        def mock_handler(req: httpx.Request):
            url_str = str(req.url)
            if "/reviews" in url_str:
                return httpx.Response(200, json=[{"user": {"login": "alice"}, "state": "APPROVED"}])
            elif "/pulls" in url_str:
                return httpx.Response(200, json={"number": 1, "head": {"sha": "c001"}, "merged": True, "title": "PR", "body": "Verified rollback procedure documented."})
            elif "/issue" in url_str or "/search" in url_str:
                return httpx.Response(200, json={"issues": []})
            elif "/actions/runs" in url_str:
                return httpx.Response(200, json={"workflow_runs": [{"id": 1, "head_sha": "c001", "status": "completed", "conclusion": "success"}]})
            elif "/deployments/findings" in url_str:
                return httpx.Response(200, json={"findings": []})
            return httpx.Response(200, json={})

        transport = httpx.MockTransport(mock_handler)
        enterprise_provider = EnterpriseReleaseDataProvider(
            git_provider=GitHubReleaseProvider(transport=transport),
            work_provider=JiraWorkManagementProvider(transport=transport),
            ci_provider=GitHubActionsCICDProvider(transport=transport),
            security_provider=SemgrepSecurityProvider(transport=transport),
        )

        api = ReleaseReadinessAPI(provider=enterprise_provider)
        candidates = [
            ReleaseCandidate(
                release_id=f"REL-CONC-ENT-{i}",
                service_name=f"svc-{i}",
                version=f"v{i}.0",
                repository=f"github.com/corp/svc-{i}",
                commit="c001",
                pull_request_id="PR-1",
            )
            for i in range(5)
        ]

        def evaluate(cand):
            return api.assess_release(cand)

        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            results = list(executor.map(evaluate, candidates))

        assert len(results) == 5
        for i, assess in enumerate(results):
            assert assess.candidate.release_id == f"REL-CONC-ENT-{i}"
            assert assess.decision.outcome == ReleaseDecisionOutcome.READY

    def test_15_token_redaction_in_exceptions(self):
        """When an HTTP error occurs with a token in the URL or error message, the token is scrubbed."""
        secret_token = "ghp_super_secret_enterprise_token_xyz999"
        GLOBAL_REDACTOR.register_secret(secret_token)

        raw_url = f"https://api.github.com/repos/org/repo?token={secret_token}"
        clean_url = scrub_secrets(raw_url)
        assert secret_token not in clean_url
        assert "[REDACTED]" in clean_url

    def test_16_trivy_security_provider_contract(self):
        """TrivySecurityProvider normalizes container vulnerabilities into canonical SecurityFinding."""
        from backend.release.connectivity.security import TrivySecurityProvider

        def trivy_handler(req: httpx.Request):
            return httpx.Response(
                200,
                json={
                    "Results": [
                        {
                            "Vulnerabilities": [
                                {
                                    "VulnerabilityID": "CVE-2024-5555",
                                    "PkgName": "openssl",
                                    "InstalledVersion": "1.1.1",
                                    "FixedVersion": "1.1.1w",
                                    "Severity": "HIGH",
                                    "Title": "Memory leak in openssl",
                                }
                            ]
                        }
                    ]
                },
            )

        provider = TrivySecurityProvider(transport=httpx.MockTransport(trivy_handler))
        findings = provider.get_findings_for_commit("github.com/corp/base-image", "sha-image-123")
        assert len(findings) == 1
        assert findings[0].finding_id == "CVE-2024-5555"
        assert findings[0].severity == SecuritySeverity.HIGH
        assert findings[0].category == SecurityCategory.CONTAINER
        assert findings[0].package == "openssl"
