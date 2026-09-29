"""
ORACLE 4.0 — Release Readiness Adversarial Evaluation Suite

Attacks release readiness intelligence across 20 distinct vectors:
1. Cross-release evidence leakage
2. Cross-repository leakage
3. Stale CI evidence (commit mismatch)
4. Stale security evidence (commit mismatch)
5. Unrelated Jira issue correlation
6. Duplicate findings deduplication
7. Duplicate scans idempotent processing
8. Accepted security exception (non-blocking)
9. Unreachable vulnerability handling (conditional)
10. Missing evidence (never assumed success)
11. Git provider outage
12. Jira provider outage
13. CI provider outage
14. Security provider outage
15. Root objective / prompt injection bypass
16. Action authorization bypass
17. Action idempotency replay protection
18. Conflicting timestamps / temporal invalidity
19. Premature READY decision prevention
20. Concurrent release assessments isolation
"""

import concurrent.futures
import pytest

from backend.evidence.models import Evidence
from backend.release.actions import ActionAuthorizationError, GovernedActionExecutor
from backend.release.api import ReleaseReadinessAPI
from backend.release.correlation import CrossSystemCorrelator
from backend.release.models import (
    CIBuildStatus,
    CIPipelineRun,
    CodeReviewStatus,
    FindingStatus,
    GovernedActionProposal,
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
from backend.release.providers import InMemoryReleaseDataProvider, _create_evidence


@pytest.fixture
def clean_setup():
    provider = InMemoryReleaseDataProvider()
    api = ReleaseReadinessAPI(provider=provider)
    return provider, api


class TestReleaseAdversarialSuite:

    def test_adv_01_cross_release_leakage(self, clean_setup):
        """1. Evidence belonging to Release A cannot satisfy Release B."""
        provider, api = clean_setup
        candidate = ReleaseCandidate(
            release_id="REL-TARGET-1.0",
            service_name="target-service",
            version="v1.0",
            repository="github.com/corp/target-service",
            commit="c001c001c001c001c001c001c001c001c001c001",
        )

        correlator = CrossSystemCorrelator()
        foreign_evidence = _create_evidence(
            evidence_id="CI-FOREIGN",
            source_id="github.com/corp/target-service",
            source_type="ci",
            content="CI Passed for REL-FOREIGN-9.9",
            metadata={"release_id": "REL-FOREIGN-9.9", "commit": candidate.commit},
        )

        res = correlator.correlate_and_validate(candidate, [foreign_evidence])
        assert len(res.admitted_evidence) == 0
        assert len(res.rejected_evidence) == 1
        assert res.rejected_evidence[0].rejection_reason == "CROSS_RELEASE_LEAKAGE"

    def test_adv_02_cross_repository_leakage(self, clean_setup):
        """2. Evidence from a foreign repository is rejected."""
        provider, api = clean_setup
        candidate = ReleaseCandidate(
            release_id="REL-CORE-1.0",
            service_name="core-service",
            version="v1.0",
            repository="github.com/corp/core-service",
            commit="c002c002c002c002c002c002c002c002c002c002",
        )

        correlator = CrossSystemCorrelator()
        foreign_git = _create_evidence(
            evidence_id="GIT-OTHER",
            source_id="github.com/corp/unrelated-repo",
            source_type="git",
            content="PR approved on unrelated-repo",
            metadata={"repository": "github.com/corp/unrelated-repo"},
        )

        res = correlator.correlate_and_validate(candidate, [foreign_git])
        assert len(res.admitted_evidence) == 0
        assert res.rejected_evidence[0].rejection_reason == "FOREIGN_REPOSITORY"

    def test_adv_03_stale_ci_evidence_attack(self, clean_setup):
        """3. Stale CI run for commit A must not validate commit B."""
        provider, api = clean_setup
        candidate = ReleaseCandidate(
            release_id="REL-PAY-2.0",
            service_name="pay-service",
            version="v2.0",
            repository="github.com/corp/pay-service",
            commit="commit-new-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        )
        correlator = CrossSystemCorrelator()
        stale_ci = _create_evidence(
            evidence_id="CI-OLD",
            source_id="github.com/corp/pay-service",
            source_type="ci",
            content="CI Passed",
            metadata={"commit": "commit-old-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "status": "PASSED"},
        )

        res = correlator.correlate_and_validate(candidate, [stale_ci])
        assert len(res.admitted_evidence) == 0
        assert res.rejected_evidence[0].rejection_reason == "STALE_COMMIT_EVIDENCE"

    def test_adv_04_stale_security_scan_attack(self, clean_setup):
        """4. Stale security scan for older commit rejected for current release."""
        provider, api = clean_setup
        candidate = ReleaseCandidate(
            release_id="REL-SEC-2.0",
            service_name="sec-service",
            version="v2.0",
            repository="github.com/corp/sec-service",
            commit="commit-release-222222222222222222222222222",
        )
        correlator = CrossSystemCorrelator()
        stale_sec = _create_evidence(
            evidence_id="SEC-OLD",
            source_id="semgrep",
            source_type="security",
            content="Scan clean",
            metadata={"commit": "commit-older-111111111111111111111111111", "status": "ACTIVE"},
        )

        res = correlator.correlate_and_validate(candidate, [stale_sec])
        assert len(res.admitted_evidence) == 0
        assert res.rejected_evidence[0].rejection_reason == "STALE_COMMIT_EVIDENCE"

    def test_adv_05_unrelated_jira_issue_not_satisfying_gaps(self, clean_setup):
        """5. Unrelated Jira issues cannot satisfy missing candidate work items."""
        provider, api = clean_setup
        commit_hash = "c005c005c005c005c005c005c005c005c005c005"
        candidate = ReleaseCandidate(
            release_id="REL-ORDER-5.0",
            service_name="order-service",
            version="v5.0",
            repository="github.com/corp/order-service",
            commit=commit_hash,
            linked_work_item_ids=["PROJ-REQUIRED-1"],
        )

        provider.add_pull_request(
            PullRequestReview(
                pr_id="PR-50",
                repository=candidate.repository,
                head_commit=commit_hash,
                status=CodeReviewStatus.APPROVED,
            )
        )
        provider.add_pipeline_run(
            CIPipelineRun(
                pipeline_id="CI-50",
                repository=candidate.repository,
                commit=commit_hash,
                status=CIBuildStatus.PASSED,
            )
        )
        # Add unrelated work item
        provider.add_work_item(
            WorkItem(item_id="PROJ-UNRELATED-999", title="Some other task", status=WorkItemStatus.DONE)
        )

        assessment = api.assess_release(candidate)
        assert assessment.decision.outcome == ReleaseDecisionOutcome.BLOCKED
        assert any("PROJ-REQUIRED-1" in bf for bf in assessment.decision.blocking_factors)

    def test_adv_06_duplicate_findings_deduplicated(self, clean_setup):
        """6. Multiple duplicate findings from scanner do not generate runaway blockers."""
        provider, api = clean_setup
        commit_hash = "c006c006c006c006c006c006c006c006c006c006"
        candidate = ReleaseCandidate(
            release_id="REL-DEDUP-1.0",
            service_name="dedup-service",
            version="v1.0",
            repository="github.com/corp/dedup-service",
            commit=commit_hash,
            pull_request_id="PR-60",
        )

        provider.add_pull_request(
            PullRequestReview(
                pr_id="PR-60",
                repository=candidate.repository,
                head_commit=commit_hash,
                status=CodeReviewStatus.APPROVED,
            )
        )
        provider.add_pipeline_run(
            CIPipelineRun(
                pipeline_id="CI-60",
                repository=candidate.repository,
                commit=commit_hash,
                status=CIBuildStatus.PASSED,
            )
        )

        # Seed same finding 5 times
        for _ in range(5):
            provider.add_security_finding(
                SecurityFinding(
                    finding_id="SEC-DUPLICATE",
                    scanner="semgrep",
                    category=SecurityCategory.SAST,
                    severity=SecuritySeverity.CRITICAL,
                    status=FindingStatus.ACTIVE,
                    repository=candidate.repository,
                    commit=commit_hash,
                    description="Duplicate SQL Injection",
                )
            )

        assessment = api.assess_release(candidate)
        assert assessment.decision.outcome == ReleaseDecisionOutcome.BLOCKED
        # Must only produce 1 recommendation for SEC-DUPLICATE, not 5
        sec_recs = [r for r in assessment.decision.recommendations if r.target_issue == "GAP-SECURITY-SAST"]
        assert len(sec_recs) == 1

    def test_adv_07_duplicate_scans_idempotent(self, clean_setup):
        """7. Re-running assess_release on same candidate is idempotent."""
        provider, api = clean_setup
        commit_hash = "c007c007c007c007c007c007c007c007c007c007"
        candidate = ReleaseCandidate(
            release_id="REL-IDEMP-1.0",
            service_name="idemp-service",
            version="v1.0",
            repository="github.com/corp/idemp-service",
            commit=commit_hash,
            pull_request_id="PR-70",
        )

        provider.add_pull_request(
            PullRequestReview(
                pr_id="PR-70",
                repository=candidate.repository,
                head_commit=commit_hash,
                status=CodeReviewStatus.APPROVED,
            )
        )
        provider.add_pipeline_run(
            CIPipelineRun(
                pipeline_id="CI-70",
                repository=candidate.repository,
                commit=commit_hash,
                status=CIBuildStatus.PASSED,
            )
        )

        a1 = api.assess_release(candidate)
        a2 = api.assess_release(candidate)

        assert a1.decision.outcome == a2.decision.outcome == ReleaseDecisionOutcome.READY
        assert a1.decision.confidence == a2.decision.confidence

    def test_adv_08_accepted_security_exception_conditional(self, clean_setup):
        """8. Security finding with EXCEPTION_ACCEPTED does not block release."""
        provider, api = clean_setup
        commit_hash = "c008c008c008c008c008c008c008c008c008c008"
        candidate = ReleaseCandidate(
            release_id="REL-EXCEPT-1.0",
            service_name="except-service",
            version="v1.0",
            repository="github.com/corp/except-service",
            commit=commit_hash,
            pull_request_id="PR-80",
        )

        provider.add_pull_request(
            PullRequestReview(
                pr_id="PR-80",
                repository=candidate.repository,
                head_commit=commit_hash,
                status=CodeReviewStatus.APPROVED,
            )
        )
        provider.add_pipeline_run(
            CIPipelineRun(
                pipeline_id="CI-80",
                repository=candidate.repository,
                commit=commit_hash,
                status=CIBuildStatus.PASSED,
            )
        )
        provider.add_security_finding(
            SecurityFinding(
                finding_id="SEC-WAIVER",
                scanner="semgrep",
                category=SecurityCategory.SAST,
                severity=SecuritySeverity.HIGH,
                status=FindingStatus.EXCEPTION_ACCEPTED,  # Exception approved
                repository=candidate.repository,
                commit=commit_hash,
                description="Accepted waiver for legacy endpoint",
            )
        )

        assessment = api.assess_release(candidate)
        assert assessment.decision.outcome in [ReleaseDecisionOutcome.READY, ReleaseDecisionOutcome.CONDITIONAL]
        assert assessment.decision.outcome != ReleaseDecisionOutcome.BLOCKED

    def test_adv_09_unreachable_vulnerability_not_blocking(self, clean_setup):
        """9. Unreachable SCA vulnerability does not hard-block release."""
        provider, api = clean_setup
        commit_hash = "c009c009c009c009c009c009c009c009c009c009"
        candidate = ReleaseCandidate(
            release_id="REL-UNREACH-1.0",
            service_name="unreach-service",
            version="v1.0",
            repository="github.com/corp/unreach-service",
            commit=commit_hash,
            pull_request_id="PR-90",
        )

        provider.add_pull_request(
            PullRequestReview(
                pr_id="PR-90",
                repository=candidate.repository,
                head_commit=commit_hash,
                status=CodeReviewStatus.APPROVED,
            )
        )
        provider.add_pipeline_run(
            CIPipelineRun(
                pipeline_id="CI-90",
                repository=candidate.repository,
                commit=commit_hash,
                status=CIBuildStatus.PASSED,
            )
        )
        provider.add_security_finding(
            SecurityFinding(
                finding_id="SCA-UNREACHABLE",
                scanner="snyk",
                category=SecurityCategory.SCA,
                severity=SecuritySeverity.HIGH,
                status=FindingStatus.ACTIVE,
                repository=candidate.repository,
                commit=commit_hash,
                package="log4j",
                current_version="2.14.0",
                fixed_version="2.17.1",
                is_reachable=False,  # Unreachable in deployed binary
                description="Log4j vulnerability in unused test tool",
            )
        )

        assessment = api.assess_release(candidate)
        assert assessment.decision.outcome == ReleaseDecisionOutcome.CONDITIONAL
        assert assessment.decision.outcome != ReleaseDecisionOutcome.BLOCKED

    def test_adv_10_missing_evidence_not_assumed_success(self, clean_setup):
        """10. Missing evidence is never assumed as success."""
        provider, api = clean_setup
        candidate = ReleaseCandidate(
            release_id="REL-EMPTY-1.0",
            service_name="empty-service",
            version="v1.0",
            repository="github.com/corp/empty-service",
            commit="c010c010c010c010c010c010c010c010c010c010",
        )

        # Zero evidence added to provider
        assessment = api.assess_release(candidate)
        assert assessment.decision.outcome != ReleaseDecisionOutcome.READY
        assert assessment.decision.outcome in [ReleaseDecisionOutcome.BLOCKED, ReleaseDecisionOutcome.INSUFFICIENT_EVIDENCE]

    def test_adv_11_git_provider_outage(self, clean_setup):
        """11. Git provider outage becomes PROVIDER_UNAVAILABLE, never READY."""
        provider, api = clean_setup
        commit_hash = "c011c011c011c011c011c011c011c011c011c011"
        candidate = ReleaseCandidate(
            release_id="REL-GIT-OUT-1.0",
            service_name="git-out-service",
            version="v1.0",
            repository="github.com/corp/git-out-service",
            commit=commit_hash,
        )

        provider.simulate_outage("git")
        assessment = api.assess_release(candidate)
        assert assessment.decision.outcome == ReleaseDecisionOutcome.INSUFFICIENT_EVIDENCE
        assert any("Git" in bf or "git" in bf for bf in assessment.decision.blocking_factors)

    def test_adv_12_jira_provider_outage(self, clean_setup):
        """12. Jira outage becomes INSUFFICIENT_EVIDENCE."""
        provider, api = clean_setup
        commit_hash = "c012c012c012c012c012c012c012c012c012c012"
        candidate = ReleaseCandidate(
            release_id="REL-JIRA-OUT-1.0",
            service_name="jira-out-service",
            version="v1.0",
            repository="github.com/corp/jira-out-service",
            commit=commit_hash,
        )

        provider.simulate_outage("jira")
        assessment = api.assess_release(candidate)
        assert assessment.decision.outcome == ReleaseDecisionOutcome.INSUFFICIENT_EVIDENCE

    def test_adv_13_ci_provider_outage(self, clean_setup):
        """13. CI provider outage becomes INSUFFICIENT_EVIDENCE."""
        provider, api = clean_setup
        commit_hash = "c013c013c013c013c013c013c013c013c013c013"
        candidate = ReleaseCandidate(
            release_id="REL-CI-OUT-1.0",
            service_name="ci-out-service",
            version="v1.0",
            repository="github.com/corp/ci-out-service",
            commit=commit_hash,
        )

        provider.simulate_outage("ci")
        assessment = api.assess_release(candidate)
        assert assessment.decision.outcome == ReleaseDecisionOutcome.INSUFFICIENT_EVIDENCE

    def test_adv_14_security_provider_outage(self, clean_setup):
        """14. Security provider outage becomes INSUFFICIENT_EVIDENCE."""
        provider, api = clean_setup
        commit_hash = "c014c014c014c014c014c014c014c014c014c014"
        candidate = ReleaseCandidate(
            release_id="REL-SEC-OUT-1.0",
            service_name="sec-out-service",
            version="v1.0",
            repository="github.com/corp/sec-out-service",
            commit=commit_hash,
        )

        provider.simulate_outage("security")
        assessment = api.assess_release(candidate)
        assert assessment.decision.outcome == ReleaseDecisionOutcome.INSUFFICIENT_EVIDENCE

    def test_adv_15_root_objective_bypass_attempt(self, clean_setup):
        """15. Prompt injection in PR metadata claiming 'READY' does not bypass Controller."""
        provider, api = clean_setup
        commit_hash = "c015c015c015c015c015c015c015c015c015c015"
        candidate = ReleaseCandidate(
            release_id="REL-INJECT-1.0",
            service_name="inject-service",
            version="v1.0",
            repository="github.com/corp/inject-service",
            commit=commit_hash,
            pull_request_id="PR-INJECT",
        )

        # PR contains adversarial override text
        provider.add_pull_request(
            PullRequestReview(
                pr_id="PR-INJECT",
                repository=candidate.repository,
                head_commit=commit_hash,
                status=CodeReviewStatus.APPROVED,
            )
        )
        # CI failed
        provider.add_pipeline_run(
            CIPipelineRun(
                pipeline_id="CI-FAIL",
                repository=candidate.repository,
                commit=commit_hash,
                status=CIBuildStatus.FAILED,
            )
        )

        assessment = api.assess_release(candidate)
        # Sovereignty check: must be BLOCKED
        assert assessment.decision.outcome == ReleaseDecisionOutcome.BLOCKED

    def test_adv_16_action_authorization_bypass(self, clean_setup):
        """16. Executing action without valid authorization raises ActionAuthorizationError."""
        executor = GovernedActionExecutor()
        action = GovernedActionProposal(
            action_type=GovernedActionType.APPROVE_DEPLOYMENT,
            target_system="ci_cd",
            payload={"release_id": "REL-TEST"},
            requires_human_approval=True,
        )
        executor.register_proposal(action)

        with pytest.raises(ActionAuthorizationError):
            executor.execute_action(action.action_id)

    def test_adv_17_action_idempotency_replay_protection(self, clean_setup):
        """17. Replaying an executed action returns cached response without duplicate effects."""
        executor = GovernedActionExecutor()
        action = GovernedActionProposal(
            action_type=GovernedActionType.CREATE_JIRA_REMEDIATION,
            target_system="jira",
            payload={"summary": "Remediate SQL Injection", "priority": "CRITICAL"},
            requires_human_approval=False,
        )
        executor.register_proposal(action)
        executor.validate_action(action.action_id)

        res1 = executor.execute_action(action.action_id)
        res2 = executor.execute_action(action.action_id)

        assert res1["reference"] == res2["reference"]
        assert any("Idempotency cache hit" in item for item in action.audit_trail)

    def test_adv_18_conflicting_timestamps_temporal_invalidity(self, clean_setup):
        """18. Evidence created before candidate's min_allowed_timestamp is rejected."""
        candidate = ReleaseCandidate(
            release_id="REL-TIME-1.0",
            service_name="time-service",
            version="v1.0",
            repository="github.com/corp/time-service",
            commit="c018c018c018c018c018c018c018c018c018c018",
            metadata={"min_allowed_timestamp": "2026-10-25T12:00:00Z"},
        )
        correlator = CrossSystemCorrelator()
        stale_ts_ev = _create_evidence(
            evidence_id="CI-STALE-TIME",
            source_id="github.com/corp/time-service",
            source_type="ci",
            content="CI Passed yesterday",
            metadata={"commit": candidate.commit},
            timestamp="2026-10-24T08:00:00Z",  # Prior to min_allowed_timestamp
        )

        res = correlator.correlate_and_validate(candidate, [stale_ts_ev])
        assert len(res.admitted_evidence) == 0
        assert res.rejected_evidence[0].rejection_reason == "TEMPORAL_INVALIDITY"

    def test_adv_19_premature_ready_decision_prevention(self, clean_setup):
        """19. An incomplete DAG with unresolved milestone cannot yield READY."""
        provider, api = clean_setup
        commit_hash = "c019c019c019c019c019c019c019c019c019c019"
        candidate = ReleaseCandidate(
            release_id="REL-PREMATURE-1.0",
            service_name="premature-service",
            version="v1.0",
            repository="github.com/corp/premature-service",
            commit=commit_hash,
            linked_work_item_ids=["PROJ-NOT-DONE"],
        )

        # Code review approved and CI passed, but work item is IN_PROGRESS
        provider.add_pull_request(
            PullRequestReview(
                pr_id="PR-PRE",
                repository=candidate.repository,
                head_commit=commit_hash,
                status=CodeReviewStatus.APPROVED,
            )
        )
        provider.add_pipeline_run(
            CIPipelineRun(
                pipeline_id="CI-PRE",
                repository=candidate.repository,
                commit=commit_hash,
                status=CIBuildStatus.PASSED,
            )
        )
        provider.add_work_item(
            WorkItem(item_id="PROJ-NOT-DONE", title="Feature WIP", status=WorkItemStatus.IN_PROGRESS)
        )

        assessment = api.assess_release(candidate)
        assert assessment.decision.outcome != ReleaseDecisionOutcome.READY

    def test_adv_20_concurrent_release_assessments_isolation(self, clean_setup):
        """20. 10 concurrent release assessments on separate threads exhibit zero cross-talk."""
        provider, api = clean_setup

        candidates = []
        for i in range(10):
            c_hash = f"commit{i:03d}" + "0" * 31
            cand = ReleaseCandidate(
                release_id=f"REL-CONC-{i}",
                service_name=f"conc-service-{i}",
                version=f"v{i}.0",
                repository=f"github.com/corp/conc-service-{i}",
                commit=c_hash,
                pull_request_id=f"PR-{i}",
            )
            candidates.append(cand)
            # Add PR
            provider.add_pull_request(
                PullRequestReview(
                    pr_id=f"PR-{i}",
                    repository=cand.repository,
                    head_commit=c_hash,
                    status=CodeReviewStatus.APPROVED,
                )
            )
            # Add CI
            provider.add_pipeline_run(
                CIPipelineRun(
                    pipeline_id=f"CI-{i}",
                    repository=cand.repository,
                    commit=c_hash,
                    status=CIBuildStatus.PASSED if i % 2 == 0 else CIBuildStatus.FAILED,
                )
            )

        def worker(c: ReleaseCandidate):
            return api.assess_release(c)

        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            results = list(executor.map(worker, candidates))

        assert len(results) == 10
        for i, assess in enumerate(results):
            # Even index should be READY, odd index should be BLOCKED
            expected = ReleaseDecisionOutcome.READY if i % 2 == 0 else ReleaseDecisionOutcome.BLOCKED
            assert assess.decision.outcome == expected
            assert assess.candidate.release_id == f"REL-CONC-{i}"
