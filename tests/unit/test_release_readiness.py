"""
ORACLE 4.0 — Release Readiness Realistic Scenarios Suite

Verifies the 10 core realistic release scenarios:
1. Clean release -> READY
2. Critical SAST finding -> BLOCKED
3. Vulnerable dependency -> BLOCKED with precise upgrade recommendation
4. Missing Jira blocker -> BLOCKED
5. CI failure -> BLOCKED
6. Missing approval -> BLOCKED / REQUIRES_REVIEW
7. Contradictory security evidence -> RECONCILIATION_REQUIRED
8. Old CI result attached to new commit -> INSUFFICIENT_EVIDENCE
9. Multiple independent blockers -> BLOCKED with prioritized reasons
10. All evidence satisfied across Git + Jira + CI + Security -> READY with complete provenance
"""

import pytest

from backend.release.api import ReleaseReadinessAPI
from backend.release.models import (
    CIBuildStatus,
    CIPipelineRun,
    CodeReviewStatus,
    FindingStatus,
    GovernedActionType,
    PullRequestReview,
    ReleaseCandidate,
    ReleaseDecisionOutcome,
    RiskLevel,
    SecurityCategory,
    SecurityFinding,
    SecuritySeverity,
    WorkItem,
    WorkItemStatus,
)
from backend.release.providers import InMemoryReleaseDataProvider


@pytest.fixture
def clean_env():
    """Sets up a provider and API with a pristine baseline."""
    provider = InMemoryReleaseDataProvider()
    api = ReleaseReadinessAPI(provider=provider)
    return provider, api


class TestReleaseReadinessScenarios:

    def test_01_clean_release_ready(self, clean_env):
        """Scenario 1: Clean release with all verified criteria -> READY."""
        provider, api = clean_env
        commit_hash = "c1a2b3d4e5f60718293a4b5c6d7e8f9012345678"
        candidate = ReleaseCandidate(
            release_id="REL-PAYMENT-4.8",
            service_name="payment-service",
            version="v4.8",
            repository="github.com/corp/payment-service",
            commit=commit_hash,
            pull_request_id="PR-582",
            linked_work_item_ids=["PROJ-912"],
        )

        # Seed clean evidence
        provider.add_pull_request(
            PullRequestReview(
                pr_id="PR-582",
                repository=candidate.repository,
                head_commit=commit_hash,
                status=CodeReviewStatus.APPROVED,
                reviewers=["alice", "bob"],
                approvers=["alice", "bob"],
                is_merged=True,
                rollback_procedure_documented=True,
            )
        )
        provider.add_work_item(
            WorkItem(
                item_id="PROJ-912",
                title="Migrate payment gateway to v3",
                status=WorkItemStatus.DONE,
                is_blocking=True,
            )
        )
        provider.add_pipeline_run(
            CIPipelineRun(
                pipeline_id="CI-812",
                repository=candidate.repository,
                commit=commit_hash,
                status=CIBuildStatus.PASSED,
                passed_tests=120,
                total_tests=120,
                failed_tests=0,
            )
        )

        assessment = api.assess_release(candidate)
        decision = assessment.decision

        assert decision.outcome == ReleaseDecisionOutcome.READY
        assert decision.risk_level == RiskLevel.LOW
        assert decision.confidence >= 0.95
        assert len(decision.blocking_factors) == 0
        assert len(decision.verified_factors) >= 4

        # Flagship summary string contains key elements
        summary = assessment.to_summary_str()
        assert "Release: payment-service v4.8" in summary
        assert "Decision: READY" in summary
        assert "Risk: LOW" in summary

    def test_02_critical_sast_finding_blocked(self, clean_env):
        """Scenario 2: Critical SAST finding -> BLOCKED."""
        provider, api = clean_env
        commit_hash = "a111b222c333d444e555f6660777188829993aaa"
        candidate = ReleaseCandidate(
            release_id="REL-AUTH-2.1",
            service_name="auth-service",
            version="v2.1",
            repository="github.com/corp/auth-service",
            commit=commit_hash,
            pull_request_id="PR-101",
        )

        # PR and CI pass
        provider.add_pull_request(
            PullRequestReview(
                pr_id="PR-101",
                repository=candidate.repository,
                head_commit=commit_hash,
                status=CodeReviewStatus.APPROVED,
                approvers=["lead-sec"],
            )
        )
        provider.add_pipeline_run(
            CIPipelineRun(
                pipeline_id="CI-901",
                repository=candidate.repository,
                commit=commit_hash,
                status=CIBuildStatus.PASSED,
            )
        )

        # Critical SAST Finding
        provider.add_security_finding(
            SecurityFinding(
                finding_id="SEC-44",
                scanner="semgrep",
                category=SecurityCategory.SAST,
                severity=SecuritySeverity.CRITICAL,
                status=FindingStatus.ACTIVE,
                repository=candidate.repository,
                commit=commit_hash,
                file="auth/tokens.py",
                line_range=(42, 45),
                cwe="CWE-287",
                description="Improper authentication verification allowing signature bypass",
                remediation_guidance="Enforce asymmetric key verification on JWT parsing",
                is_exploitable_in_context=True,
            )
        )

        assessment = api.assess_release(candidate)
        decision = assessment.decision

        assert decision.outcome == ReleaseDecisionOutcome.BLOCKED
        assert decision.risk_level == RiskLevel.CRITICAL
        assert any("SEC-44" in bf for bf in decision.blocking_factors)
        assert any("Remediate" in r.action_summary or "SEC-44" in r.rationale for r in decision.recommendations)

        # Governed action proposal generated
        remediation_actions = [a for a in decision.governed_actions if a.action_type == GovernedActionType.CREATE_JIRA_REMEDIATION]
        assert len(remediation_actions) > 0

    def test_03_vulnerable_dependency_blocked_with_recommendation(self, clean_env):
        """Scenario 3: Reachable vulnerable SCA dependency -> BLOCKED with precise version upgrade."""
        provider, api = clean_env
        commit_hash = "beef111122223333444455556666777788889999"
        candidate = ReleaseCandidate(
            release_id="REL-ORDER-1.4",
            service_name="order-service",
            version="v1.4",
            repository="github.com/corp/order-service",
            commit=commit_hash,
            pull_request_id="PR-304",
        )

        provider.add_pull_request(
            PullRequestReview(
                pr_id="PR-304",
                repository=candidate.repository,
                head_commit=commit_hash,
                status=CodeReviewStatus.APPROVED,
            )
        )
        provider.add_pipeline_run(
            CIPipelineRun(
                pipeline_id="CI-401",
                repository=candidate.repository,
                commit=commit_hash,
                status=CIBuildStatus.PASSED,
            )
        )

        # Reachable vulnerable dependency
        provider.add_security_finding(
            SecurityFinding(
                finding_id="SCA-99",
                scanner="snyk",
                category=SecurityCategory.SCA,
                severity=SecuritySeverity.HIGH,
                status=FindingStatus.ACTIVE,
                repository=candidate.repository,
                commit=commit_hash,
                package="urllib3",
                current_version="1.26.4",
                fixed_version="1.26.18",
                cve="CVE-2023-45803",
                description="Request body stripping vulnerability in HTTP redirects",
                is_reachable=True,
            )
        )

        assessment = api.assess_release(candidate)
        decision = assessment.decision

        assert decision.outcome == ReleaseDecisionOutcome.BLOCKED
        assert any("urllib3" in bf for bf in decision.blocking_factors)

        # Verified precise evidence-grounded recommendation
        upgrade_recs = [r for r in decision.recommendations if "Upgrade urllib3 from 1.26.4 to 1.26.18" in r.action_summary]
        assert len(upgrade_recs) == 1

    def test_04_missing_jira_blocker(self, clean_env):
        """Scenario 4: Linked Jira blocker is not DONE -> BLOCKED."""
        provider, api = clean_env
        commit_hash = "fa55fa55fa55fa55fa55fa55fa55fa55fa55fa55"
        candidate = ReleaseCandidate(
            release_id="REL-CHECKOUT-3.0",
            service_name="checkout-service",
            version="v3.0",
            repository="github.com/corp/checkout-service",
            commit=commit_hash,
            pull_request_id="PR-77",
            linked_work_item_ids=["PROJ-501"],
        )

        provider.add_pull_request(
            PullRequestReview(
                pr_id="PR-77",
                repository=candidate.repository,
                head_commit=commit_hash,
                status=CodeReviewStatus.APPROVED,
            )
        )
        provider.add_pipeline_run(
            CIPipelineRun(
                pipeline_id="CI-100",
                repository=candidate.repository,
                commit=commit_hash,
                status=CIBuildStatus.PASSED,
            )
        )

        # Unresolved blocking issue
        provider.add_work_item(
            WorkItem(
                item_id="PROJ-501",
                title="Fix race condition in checkout cart reservation",
                status=WorkItemStatus.BLOCKED,
                is_blocking=True,
            )
        )

        assessment = api.assess_release(candidate)
        decision = assessment.decision

        assert decision.outcome == ReleaseDecisionOutcome.BLOCKED
        assert any("PROJ-501" in bf for bf in decision.blocking_factors)

    def test_05_ci_failure_blocked(self, clean_env):
        """Scenario 5: CI test failure -> BLOCKED with test failure diagnostic."""
        provider, api = clean_env
        commit_hash = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
        candidate = ReleaseCandidate(
            release_id="REL-INV-1.9",
            service_name="inventory-service",
            version="v1.9",
            repository="github.com/corp/inventory-service",
            commit=commit_hash,
            pull_request_id="PR-410",
        )

        provider.add_pull_request(
            PullRequestReview(
                pr_id="PR-410",
                repository=candidate.repository,
                head_commit=commit_hash,
                status=CodeReviewStatus.APPROVED,
            )
        )

        # Failing CI
        provider.add_pipeline_run(
            CIPipelineRun(
                pipeline_id="CI-777",
                repository=candidate.repository,
                commit=commit_hash,
                status=CIBuildStatus.FAILED,
                total_tests=80,
                passed_tests=76,
                failed_tests=4,
                failed_jobs=["unit-tests-py310", "integration-tests"],
            )
        )

        assessment = api.assess_release(candidate)
        decision = assessment.decision

        assert decision.outcome == ReleaseDecisionOutcome.BLOCKED
        assert decision.risk_level == RiskLevel.CRITICAL
        assert any("CI validation failure" in bf for bf in decision.blocking_factors)

    def test_06_missing_code_review_approval(self, clean_env):
        """Scenario 6: Missing code review approval -> BLOCKED."""
        provider, api = clean_env
        commit_hash = "1234567890abcdef1234567890abcdef12345678"
        candidate = ReleaseCandidate(
            release_id="REL-BILLING-2.0",
            service_name="billing-service",
            version="v2.0",
            repository="github.com/corp/billing-service",
            commit=commit_hash,
            pull_request_id="PR-888",
        )

        # PR has changes requested
        provider.add_pull_request(
            PullRequestReview(
                pr_id="PR-888",
                repository=candidate.repository,
                head_commit=commit_hash,
                status=CodeReviewStatus.CHANGES_REQUESTED,
                reviewers=["charlie"],
                approvers=[],
            )
        )
        provider.add_pipeline_run(
            CIPipelineRun(
                pipeline_id="CI-202",
                repository=candidate.repository,
                commit=commit_hash,
                status=CIBuildStatus.PASSED,
            )
        )

        assessment = api.assess_release(candidate)
        decision = assessment.decision

        assert decision.outcome == ReleaseDecisionOutcome.BLOCKED
        assert any("Code review incomplete" in bf for bf in decision.blocking_factors)

    def test_07_contradictory_security_evidence_reconciliation(self, clean_env):
        """Scenario 7: Contradictory security evidence -> REQUIRES_REVIEW and RECONCILIATION_REQUIRED."""
        provider, api = clean_env
        commit_hash = "ababcdcd12123434ababcdcd12123434ababcdcd"
        candidate = ReleaseCandidate(
            release_id="REL-ANALYTICS-3.5",
            service_name="analytics-service",
            version="v3.5",
            repository="github.com/corp/analytics-service",
            commit=commit_hash,
            pull_request_id="PR-99",
        )

        provider.add_pull_request(
            PullRequestReview(
                pr_id="PR-99",
                repository=candidate.repository,
                head_commit=commit_hash,
                status=CodeReviewStatus.APPROVED,
            )
        )
        provider.add_pipeline_run(
            CIPipelineRun(
                pipeline_id="CI-303",
                repository=candidate.repository,
                commit=commit_hash,
                status=CIBuildStatus.PASSED,
            )
        )

        # Scanner reports finding is ACTIVE CRITICAL
        provider.add_security_finding(
            SecurityFinding(
                finding_id="SEC-99",
                scanner="trivy",
                category=SecurityCategory.CONTAINER,
                severity=SecuritySeverity.CRITICAL,
                status=FindingStatus.ACTIVE,
                repository=candidate.repository,
                commit=commit_hash,
                description="Remote code execution in base image",
            )
        )
        # Contradictory record claims finding is EXCEPTION_ACCEPTED
        provider.add_security_finding(
            SecurityFinding(
                finding_id="SEC-99",
                scanner="secops-portal",
                category=SecurityCategory.CONTAINER,
                severity=SecuritySeverity.CRITICAL,
                status=FindingStatus.EXCEPTION_ACCEPTED,
                repository=candidate.repository,
                commit=commit_hash,
                description="Waiver accepted by security architect",
            )
        )

        assessment = api.assess_release(candidate)
        decision = assessment.decision

        assert decision.outcome == ReleaseDecisionOutcome.REQUIRES_REVIEW
        assert decision.investigation_status == "RECONCILIATION_REQUIRED"
        assert len(assessment.contradictions) > 0
        assert any("contradiction" in bf.lower() for bf in decision.blocking_factors)

    def test_08_old_ci_result_on_new_commit_insufficient_evidence(self, clean_env):
        """Scenario 8: Old CI result attached to new commit -> INSUFFICIENT_EVIDENCE (temporal commit safety)."""
        provider, api = clean_env
        old_commit = "1111111111111111111111111111111111111111"
        new_commit = "2222222222222222222222222222222222222222"

        candidate = ReleaseCandidate(
            release_id="REL-SHIP-1.1",
            service_name="shipping-service",
            version="v1.1",
            repository="github.com/corp/shipping-service",
            commit=new_commit,  # New commit
            pull_request_id="PR-12",
        )

        provider.add_pull_request(
            PullRequestReview(
                pr_id="PR-12",
                repository=candidate.repository,
                head_commit=new_commit,
                status=CodeReviewStatus.APPROVED,
            )
        )

        # CI was run on old_commit, NOT new_commit
        provider.add_pipeline_run(
            CIPipelineRun(
                pipeline_id="CI-OLD",
                repository=candidate.repository,
                commit=old_commit,  # Mismatched commit
                status=CIBuildStatus.PASSED,
            )
        )

        assessment = api.assess_release(candidate)
        decision = assessment.decision

        assert decision.outcome == ReleaseDecisionOutcome.INSUFFICIENT_EVIDENCE
        assert any("Stale validation" in bf or "INSUFFICIENT_EVIDENCE" in bf for bf in decision.blocking_factors)

    def test_09_multiple_independent_blockers(self, clean_env):
        """Scenario 9: Multiple independent blockers -> BLOCKED with prioritized reasons."""
        provider, api = clean_env
        commit_hash = "9999888877776666555544443333222211110000"
        candidate = ReleaseCandidate(
            release_id="REL-CORE-5.0",
            service_name="core-api",
            version="v5.0",
            repository="github.com/corp/core-api",
            commit=commit_hash,
            pull_request_id="PR-500",
            linked_work_item_ids=["PROJ-101", "PROJ-102"],
        )

        # 1. PR review pending
        provider.add_pull_request(
            PullRequestReview(
                pr_id="PR-500",
                repository=candidate.repository,
                head_commit=commit_hash,
                status=CodeReviewStatus.PENDING,
                rollback_procedure_documented=False,  # Missing rollback
            )
        )
        # 2. Jira blockers
        provider.add_work_item(
            WorkItem(item_id="PROJ-101", title="Blocker 1", status=WorkItemStatus.OPEN, is_blocking=True)
        )
        # 3. CI failure
        provider.add_pipeline_run(
            CIPipelineRun(
                pipeline_id="CI-FAIL",
                repository=candidate.repository,
                commit=commit_hash,
                status=CIBuildStatus.FAILED,
                failed_tests=5,
            )
        )
        # 4. Critical Security finding
        provider.add_security_finding(
            SecurityFinding(
                finding_id="SEC-CRIT",
                scanner="semgrep",
                category=SecurityCategory.SAST,
                severity=SecuritySeverity.CRITICAL,
                status=FindingStatus.ACTIVE,
                repository=candidate.repository,
                commit=commit_hash,
                description="Remote code execution",
            )
        )
        # 5. Active production incident
        provider.add_work_item(
            WorkItem(
                item_id="INC-999",
                title="Core API Outage in us-east-1",
                status=WorkItemStatus.IN_PROGRESS,
                priority="P1",
                is_incident=True,
                linked_releases=["core-api"],
            )
        )

        assessment = api.assess_release(candidate)
        decision = assessment.decision

        assert decision.outcome == ReleaseDecisionOutcome.BLOCKED
        assert decision.risk_level == RiskLevel.CRITICAL
        # Must identify at least 4 distinct blockers
        assert len(decision.blocking_factors) >= 4
        assert len(decision.recommendations) >= 3

    def test_10_all_evidence_satisfied_e2e_cross_system(self, clean_env):
        """Scenario 10: Multi-system release (Git + Jira + CI + Security) -> READY with complete provenance."""
        provider, api = clean_env
        commit_hash = "7777777777777777777777777777777777777777"
        candidate = ReleaseCandidate(
            release_id="REL-IDENTITY-2.4",
            service_name="identity-service",
            version="v2.4",
            repository="github.com/corp/identity-service",
            commit=commit_hash,
            pull_request_id="PR-240",
            linked_work_item_ids=["PROJ-777", "PROJ-778"],
        )

        provider.add_pull_request(
            PullRequestReview(
                pr_id="PR-240",
                repository=candidate.repository,
                head_commit=commit_hash,
                status=CodeReviewStatus.APPROVED,
                reviewers=["sec-lead", "arch-lead"],
                approvers=["sec-lead", "arch-lead"],
                is_merged=True,
                rollback_procedure_documented=True,
            )
        )
        provider.add_work_item(
            WorkItem(item_id="PROJ-777", title="OAuth2 Token Revocation", status=WorkItemStatus.DONE)
        )
        provider.add_work_item(
            WorkItem(item_id="PROJ-778", title="PKCE Verification", status=WorkItemStatus.DONE)
        )
        provider.add_pipeline_run(
            CIPipelineRun(
                pipeline_id="CI-IDENTITY-240",
                repository=candidate.repository,
                commit=commit_hash,
                status=CIBuildStatus.PASSED,
                passed_tests=350,
                total_tests=350,
            )
        )
        provider.add_security_finding(
            SecurityFinding(
                finding_id="SEC-LOW",
                scanner="semgrep",
                category=SecurityCategory.SAST,
                severity=SecuritySeverity.LOW,
                status=FindingStatus.ACTIVE,
                repository=candidate.repository,
                commit=commit_hash,
                description="Minor header recommendation",
            )
        )

        assessment = api.assess_release(candidate)
        decision = assessment.decision

        assert decision.outcome == ReleaseDecisionOutcome.READY
        assert decision.risk_level == RiskLevel.LOW
        assert decision.confidence == 0.99
        assert decision.provenance["candidate_commit"] == commit_hash
        assert decision.provenance["engine"] == "ORACLE Controller 4.0"

        # Check API getters
        assert api.get_decision(candidate.release_id) == decision
        assert len(api.get_evidence(candidate.release_id)) > 0
        assert api.get_assessment(assessment.assessment_id) == assessment
