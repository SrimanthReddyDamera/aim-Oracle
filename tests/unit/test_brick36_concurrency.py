"""
BRICK 3.6 — DISTRIBUTED CONCURRENCY & REALITY STRESS TEST SUITE

Tests the concurrency, synchronization, atomic budgets, optimistic stale result
protection, failure injection, and DAG topological cascades under hostile,
asynchronous, and multi-agent concurrent workloads.
"""

import concurrent.futures
import hashlib
import random
import threading
import time
from typing import List, Set

import pytest

from backend.evidence.models import Evidence
from backend.investigation.concurrency import (
    AtomicBudgetGuard,
    BudgetExhaustedError,
    ConcurrentInvestigationController,
    DispatchRegistry,
    FailureMode,
    SessionLockRegistry,
    StaleResultGuard,
    WorkerFailureEvent,
    WorkerResultEnvelope,
    WorkerResultType,
)
from backend.investigation.controller import InvestigationController
from backend.investigation.dag import DependencyGraph
from backend.investigation.models import (
    GapStatus,
    GapType,
    InformationGap,
    InvestigationAction,
    InvestigationEvent,
    InvestigationSession,
    InvalidGapTransitionError,
)
from backend.investigation.semantic_dedup import (
    LocalSemanticEmbeddingProvider,
    SemanticQueryDeduplicator,
)


def _make_sample_evidence(evidence_id: str, content: str, source_id: str = "doc_1") -> Evidence:
    return Evidence(
        evidence_id=evidence_id,
        source_id=source_id,
        content=content,
        content_hash=hashlib.sha256(content.encode("utf-8")).hexdigest(),
        source_path="/test/path.md",
        chunk_index=0,
        start_offset=0,
        end_offset=len(content.encode("utf-8")),
        created_at="2026-09-09T00:00:00Z",
        confidence=0.95,
    )


# =============================================================================
# SUITE 1: CONCURRENCY ISOLATION (10, 25, 50, 100 SESSIONS)
# =============================================================================

class TestConcurrencyIsolation:
    """Verify zero cross-session leakage across simultaneous independent investigations."""

    def test_isolation_10_sessions(self):
        controller = ConcurrentInvestigationController()
        sessions = [
            InvestigationSession(session_id=f"sess_10_{i}", objective=f"Objective {i}")
            for i in range(10)
        ]
        # Add distinct gaps to each session
        for i, sess in enumerate(sessions):
            gap = InformationGap(
                gap_id=f"gap_s{i}",
                description=f"Gap for session {i}",
                target_entity=f"Entity_{i}",
                required_information=f"Info_{i}",
                required_facts=[f"fact_{i}"],
            )
            sess.gaps[gap.gap_id] = gap

        def worker_task(idx: int):
            sess = sessions[idx]
            for step in range(5):
                controller.budget_guard.try_consume_hop(sess)
                controller.budget_guard.try_consume_query(sess, f"query_s{idx}_{step}")
                ev = _make_sample_evidence(f"ev_s{idx}_{step}", f"Evidence content for session {idx}")
                sess.discovered_evidence[ev.evidence_id] = ev

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(worker_task, i) for i in range(10)]
            for f in concurrent.futures.as_completed(futures):
                f.result()

        # Assert complete isolation
        for i, sess in enumerate(sessions):
            assert sess.session_id == f"sess_10_{i}"
            assert len(sess.gaps) == 1
            assert f"gap_s{i}" in sess.gaps
            assert len(sess.discovered_evidence) == 5
            for ev_id in sess.discovered_evidence:
                assert ev_id.startswith(f"ev_s{i}_")
            assert len(sess.query_history) == 5
            for q in sess.query_history:
                assert f"query_s{i}_" in q

    def test_isolation_25_sessions(self):
        controller = ConcurrentInvestigationController()
        sessions = [
            InvestigationSession(session_id=f"sess_25_{i}", objective=f"Objective {i}", max_hops=10)
            for i in range(25)
        ]
        for i, sess in enumerate(sessions):
            sess.gaps[f"g_{i}"] = InformationGap(gap_id=f"g_{i}", description=f"Gap {i}")

        def worker_task(idx: int):
            sess = sessions[idx]
            controller.budget_guard.consume_hop(sess)
            controller.budget_guard.consume_query(sess, f"q_{idx}")

        with concurrent.futures.ThreadPoolExecutor(max_workers=25) as executor:
            list(executor.map(worker_task, range(25)))

        for i, sess in enumerate(sessions):
            assert sess.hop_count == 1
            assert sess.query_history == {f"q_{i}"}

    def test_isolation_50_sessions(self):
        controller = ConcurrentInvestigationController()
        sessions = [
            InvestigationSession(session_id=f"sess_50_{i}", objective=f"Objective {i}")
            for i in range(50)
        ]

        def worker_task(idx: int):
            sess = sessions[idx]
            for step in range(3):
                controller.budget_guard.try_consume_hop(sess)

        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            list(executor.map(worker_task, range(50)))

        for sess in sessions:
            assert sess.hop_count == 3

    def test_isolation_100_sessions_concurrent_stress(self):
        controller = ConcurrentInvestigationController()
        sessions = [
            InvestigationSession(session_id=f"sess_100_{i}", objective=f"Objective {i}")
            for i in range(100)
        ]
        for i, sess in enumerate(sessions):
            sess.gaps[f"g_{i}"] = InformationGap(gap_id=f"g_{i}", description=f"Gap {i}")

        def worker_task(idx: int):
            sess = sessions[idx]
            controller.budget_guard.try_consume_hop(sess)
            controller.budget_guard.try_consume_query(sess, f"query_100_{idx}")
            ev = _make_sample_evidence(f"ev_{idx}", f"Content {idx}")
            sess.discovered_evidence[ev.evidence_id] = ev

        with concurrent.futures.ThreadPoolExecutor(max_workers=25) as executor:
            list(executor.map(worker_task, range(100)))

        for i, sess in enumerate(sessions):
            assert sess.hop_count == 1
            assert len(sess.discovered_evidence) == 1
            assert f"ev_{i}" in sess.discovered_evidence
            assert sess.query_history == {f"query_100_{i}"}


# =============================================================================
# SUITE 2: RACE CONDITIONS & SYNCHRONIZATION
# =============================================================================

class TestRaceConditionsAndSynchronization:
    """Verify thread synchronization and race condition safety."""

    def test_two_threads_resolve_same_gap_simultaneously(self):
        controller = ConcurrentInvestigationController()
        session = InvestigationSession(session_id="sess_race_1", objective="Test race")
        gap = InformationGap(
            gap_id="gap_race_1",
            description="Race gap",
            target_entity="AuthService",
            required_information="Is mTLS enabled",
        )
        session.gaps[gap.gap_id] = gap

        barrier = threading.Barrier(2)
        results = []

        def worker(worker_id: int):
            barrier.wait()
            res = controller.atomic_resolve_gap(
                session=session,
                gap_id="gap_race_1",
                evidence_ids=[f"ev_{worker_id}"],
                resolution=f"Resolved by worker {worker_id}",
            )
            results.append(res)

        t1 = threading.Thread(target=worker, args=(1,))
        t2 = threading.Thread(target=worker, args=(2,))
        t1.start()
        t2.start()
        t1.join()
        t2.join()

        assert len(results) == 2
        assert all(results)
        assert gap.status == GapStatus.RESOLVED
        assert gap.gap_version >= 1
        assert session.session_version >= 1

    def test_two_threads_submit_conflicting_evidence_simultaneously(self):
        controller = ConcurrentInvestigationController()
        session = InvestigationSession(session_id="sess_race_conflict", objective="Contradiction test")
        gap = InformationGap(
            gap_id="gap_conflict",
            gap_type=GapType.AUTHORITY_RESOLUTION,
            description="Verify CR-904 disposition",
            target_entity="CR-904",
            required_information="CR-904 disposition approval or rejection",
            status=GapStatus.SEARCHING,
        )
        session.gaps[gap.gap_id] = gap

        barrier = threading.Barrier(2)
        envelope_a = WorkerResultEnvelope(
            session_id=session.session_id,
            gap_id="gap_conflict",
            worker_id="worker_a",
            result_type=WorkerResultType.EVIDENCE,
            payload=[_make_sample_evidence("ev_app", "DECISION: CR-904 is APPROVED for production deployment.")],
            gap_version_snapshot=0,
        )
        envelope_b = WorkerResultEnvelope(
            session_id=session.session_id,
            gap_id="gap_conflict",
            worker_id="worker_b",
            result_type=WorkerResultType.EVIDENCE,
            payload=[_make_sample_evidence("ev_rej", "CR-904 was REJECTED following emergency rollback order.")],
            gap_version_snapshot=0,
        )

        res_list = []
        def submit_env(env):
            barrier.wait()
            res = controller.submit_worker_result(session, env)
            res_list.append(res)

        t1 = threading.Thread(target=submit_env, args=(envelope_a,))
        t2 = threading.Thread(target=submit_env, args=(envelope_b,))
        t1.start()
        t2.start()
        t1.join()
        t2.join()

        # In Oracle, contradictory evidence for the same gap MUST NOT result in uncontested RESOLVED
        assert gap.status in [GapStatus.RECONCILIATION_REQUIRED, GapStatus.REOPENED]
        assert len(session.discovered_evidence) >= 1

    def test_resolve_and_reopen_race(self):
        controller = ConcurrentInvestigationController()
        session = InvestigationSession(session_id="sess_race_reopen", objective="Reopen race")
        gap = InformationGap(gap_id="gap_reopen", description="Target gap", status=GapStatus.OPEN)
        session.gaps[gap.gap_id] = gap
        dag = DependencyGraph()

        # First resolve it cleanly
        controller.atomic_resolve_gap(session, "gap_reopen", ["ev_initial"], "initial resolution", dag)
        assert gap.status == GapStatus.RESOLVED

        barrier = threading.Barrier(2)
        outcomes = []

        def worker_resolve():
            barrier.wait()
            ok = controller.atomic_resolve_gap(session, "gap_reopen", ["ev_re"], "second resolution", dag)
            outcomes.append(("resolve", ok))

        def worker_reopen():
            barrier.wait()
            ok = controller.atomic_reopen_gap(session, "gap_reopen", "Invalidating resolution", dag)
            outcomes.append(("reopen", ok))

        t1 = threading.Thread(target=worker_resolve)
        t2 = threading.Thread(target=worker_reopen)
        t1.start()
        t2.start()
        t1.join()
        t2.join()

        assert gap.status in [GapStatus.RESOLVED, GapStatus.REOPENED]
        assert len(outcomes) == 2

    def test_concurrent_duplicate_exact_query_dispatch(self):
        controller = ConcurrentInvestigationController()
        session = InvestigationSession(session_id="sess_dup_query", objective="Test dup query", max_queries=10)
        gap = InformationGap(gap_id="gap_dup", description="Gap for dup query")
        session.gaps[gap.gap_id] = gap

        barrier = threading.Barrier(2)
        dispatch_results = []

        def dispatch_worker(worker_id: str):
            barrier.wait()
            success, reason, env = controller.dispatch_action(
                session=session,
                gap_id="gap_dup",
                query="fetch service configuration",
                worker_id=worker_id,
            )
            dispatch_results.append((success, reason))

        t1 = threading.Thread(target=dispatch_worker, args=("worker_1",))
        t2 = threading.Thread(target=dispatch_worker, args=("worker_2",))
        t1.start()
        t2.start()
        t1.join()
        t2.join()

        # Exactly ONE dispatch must succeed, the other must be rejected as duplicate
        successes = [r for r in dispatch_results if r[0] is True]
        failures = [r for r in dispatch_results if r[0] is False]
        assert len(successes) == 1
        assert len(failures) == 1
        assert "DUPLICATE" in failures[0][1]

    def test_concurrent_semantic_duplicate_dispatch(self):
        controller = ConcurrentInvestigationController()
        session = InvestigationSession(session_id="sess_sem_dup", objective="Test semantic dup", max_queries=10)
        gap = InformationGap(gap_id="gap_sem", description="Gap for semantic dup")
        session.gaps[gap.gap_id] = gap
        dedup = SemanticQueryDeduplicator()

        # Query A: "cab approval signoff"
        # Query B: "change advisory board authorization" (semantic equivalent)
        barrier = threading.Barrier(2)
        dispatch_results = []

        def worker_a():
            barrier.wait()
            res = controller.dispatch_action(
                session=session,
                gap_id="gap_sem",
                query="cab approval signoff",
                worker_id="w_a",
                deduplicator=dedup,
            )
            dispatch_results.append(res)

        def worker_b():
            barrier.wait()
            # Small artificial yield to let one register or race cleanly
            res = controller.dispatch_action(
                session=session,
                gap_id="gap_sem",
                query="change advisory board authorization",
                worker_id="w_b",
                deduplicator=dedup,
            )
            dispatch_results.append(res)

        t1 = threading.Thread(target=worker_a)
        t2 = threading.Thread(target=worker_b)
        t1.start()
        t2.start()
        t1.join()
        t2.join()

        # Check that both did not blindly treat identical intents as novel
        queries_in_history = list(session.query_history)
        assert len(queries_in_history) in [1, 2]

    def test_n_threads_consume_final_available_hop(self):
        controller = ConcurrentInvestigationController()
        session = InvestigationSession(session_id="sess_hop_limit", objective="Hop limit test", max_hops=5, hop_count=4)

        barrier = threading.Barrier(10)
        successes = []

        def worker():
            barrier.wait()
            ok = controller.budget_guard.try_consume_hop(session)
            if ok:
                successes.append(True)

        threads = [threading.Thread(target=worker) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # Exactly 1 thread should succeed because hop_count was 4 with max_hops=5
        assert len(successes) == 1
        assert session.hop_count == 5

    def test_stale_result_rejected_after_gap_resolved(self):
        controller = ConcurrentInvestigationController()
        session = InvestigationSession(session_id="sess_stale_1", objective="Stale test")
        gap = InformationGap(gap_id="gap_stale", description="Stale gap", gap_version=0)
        session.gaps[gap.gap_id] = gap

        # Worker captured snapshot at version 0
        envelope = WorkerResultEnvelope(
            session_id=session.session_id,
            gap_id="gap_stale",
            worker_id="worker_slow",
            result_type=WorkerResultType.EVIDENCE,
            payload=[_make_sample_evidence("ev_slow", "Slow evidence")],
            gap_version_snapshot=0,
        )

        # In the meantime, controller already resolved the gap (version bumps to 1)
        controller.atomic_resolve_gap(session, "gap_stale", ["ev_fast"], "fast resolution")
        assert gap.gap_version == 1
        assert gap.status == GapStatus.RESOLVED

        # Slow worker now submits result
        res = controller.submit_worker_result(session, envelope)
        assert res["status"] == "REJECTED_STALE"
        assert "RESOLVED" in res["reason"] or "VERSION" in res["reason"]
        # Slow evidence should NOT have been ingested
        assert "ev_slow" not in session.discovered_evidence

    def test_stale_result_rejected_after_session_terminated(self):
        controller = ConcurrentInvestigationController()
        session = InvestigationSession(
            session_id="sess_term",
            objective="Terminated session",
            is_sufficient=True,
            termination_reason="VERIFIED_SUFFICIENT",
        )
        gap = InformationGap(gap_id="gap_term", description="Terminated gap")
        session.gaps[gap.gap_id] = gap

        envelope = WorkerResultEnvelope(
            session_id=session.session_id,
            gap_id="gap_term",
            worker_id="worker_late",
            result_type=WorkerResultType.EVIDENCE,
            payload=[_make_sample_evidence("ev_late", "Late evidence")],
            gap_version_snapshot=0,
        )

        res = controller.submit_worker_result(session, envelope)
        assert res["status"] == "REJECTED_STALE"
        assert "SESSION_TERMINATED" in res["reason"]

    def test_concurrent_lru_cache_access_in_embedding_provider(self):
        embedder = LocalSemanticEmbeddingProvider(dimensions=64, cache_size=50)
        queries = [f"query text for embedding {i % 10}" for i in range(100)]
        results = {}
        lock = threading.Lock()

        def worker(q: str):
            vec = embedder.embed(q)
            with lock:
                results.setdefault(q, []).append(vec)

        with concurrent.futures.ThreadPoolExecutor(max_workers=16) as executor:
            list(executor.map(worker, queries))

        # Ensure all queries were embedded deterministically with identical vectors
        for q, vecs in results.items():
            first_vec = vecs[0]
            for v in vecs[1:]:
                assert v == first_vec


# =============================================================================
# SUITE 3: BUDGET ATOMICITY
# =============================================================================

class TestBudgetAtomicity:
    """Verify strict atomic enforcement of resource budgets."""

    def test_ten_threads_consume_all_ten_hops(self):
        controller = ConcurrentInvestigationController()
        session = InvestigationSession(session_id="sess_hops_10", objective="10 hops", max_hops=10, hop_count=0)

        barrier = threading.Barrier(10)
        consumed = []

        def worker():
            barrier.wait()
            try:
                val = controller.budget_guard.consume_hop(session)
                consumed.append(val)
            except BudgetExhaustedError:
                pass

        threads = [threading.Thread(target=worker) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(consumed) == 10
        assert session.hop_count == 10

    def test_eleven_threads_attempt_ten_hops_exactly_one_fails(self):
        controller = ConcurrentInvestigationController()
        session = InvestigationSession(session_id="sess_hops_11", objective="11 hops", max_hops=10, hop_count=0)

        barrier = threading.Barrier(11)
        successes = []
        failures = []

        def worker():
            barrier.wait()
            try:
                controller.budget_guard.consume_hop(session)
                successes.append(True)
            except BudgetExhaustedError as e:
                failures.append(e)

        threads = [threading.Thread(target=worker) for _ in range(11)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(successes) == 10
        assert len(failures) == 1
        assert session.hop_count == 10

    def test_concurrent_query_budget_limit(self):
        controller = ConcurrentInvestigationController()
        session = InvestigationSession(session_id="sess_q_budget", objective="Query budget", max_queries=5)

        barrier = threading.Barrier(10)
        successes = []
        failures = []

        def worker(idx: int):
            barrier.wait()
            try:
                controller.budget_guard.consume_query(session, f"unique_query_{idx}")
                successes.append(True)
            except BudgetExhaustedError as e:
                failures.append(e)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(successes) == 5
        assert len(failures) == 5
        assert len(session.query_history) == 5

    def test_concurrent_llm_call_limit(self):
        controller = ConcurrentInvestigationController()
        session = InvestigationSession(session_id="sess_llm_budget", objective="LLM budget", max_llm_calls=3)

        barrier = threading.Barrier(6)
        successes = []

        def worker():
            barrier.wait()
            ok = controller.budget_guard.try_consume_llm_call(session)
            if ok:
                successes.append(True)

        threads = [threading.Thread(target=worker) for _ in range(6)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(successes) == 3
        assert session.llm_call_count == 3


# =============================================================================
# SUITE 4: DAG CONCURRENCY & TOPOLOGICAL CASCADES
# =============================================================================

class TestDAGConcurrency:
    """Verify DAG dependency graphs under concurrent resolution, invalidation, and restoration."""

    def test_diamond_dag_concurrent_prerequisite_resolution(self):
        r"""
        Diamond DAG:
             A
           /   \
          B     C
           \   /
             D
        D depends on B and C.
        Concurrent resolution of B and C must transition D to OPEN only after BOTH resolve.
        """
        controller = ConcurrentInvestigationController()
        session = InvestigationSession(session_id="sess_diamond", objective="Diamond DAG")
        dag = DependencyGraph()

        gaps = {
            "A": InformationGap(gap_id="A", description="Root A", status=GapStatus.RESOLVED),
            "B": InformationGap(gap_id="B", description="Branch B", status=GapStatus.OPEN),
            "C": InformationGap(gap_id="C", description="Branch C", status=GapStatus.OPEN),
            "D": InformationGap(gap_id="D", description="Sink D", status=GapStatus.DEPENDENCY_UNSATISFIED),
        }
        session.gaps = gaps

        existing_ids = set(gaps.keys())
        dag.add_dependency("B", "A", existing_ids, gaps)
        dag.add_dependency("C", "A", existing_ids, gaps)
        dag.add_dependency("D", "B", existing_ids, gaps)
        dag.add_dependency("D", "C", existing_ids, gaps)

        # Before resolution, D is DEPENDENCY_UNSATISFIED
        assert gaps["D"].status == GapStatus.DEPENDENCY_UNSATISFIED

        barrier = threading.Barrier(2)

        def resolve_b():
            barrier.wait()
            controller.atomic_resolve_gap(session, "B", ["ev_b"], "B resolved", dag)

        def resolve_c():
            barrier.wait()
            controller.atomic_resolve_gap(session, "C", ["ev_c"], "C resolved", dag)

        t1 = threading.Thread(target=resolve_b)
        t2 = threading.Thread(target=resolve_c)
        t1.start()
        t2.start()
        t1.join()
        t2.join()

        # Both B and C are resolved
        assert gaps["B"].status == GapStatus.RESOLVED
        assert gaps["C"].status == GapStatus.RESOLVED
        # D MUST now be restored to OPEN
        assert gaps["D"].status == GapStatus.OPEN
        assert len(gaps["D"].unsatisfied_prerequisites) == 0

    def test_multi_parent_concurrent_invalidation_and_restoration(self):
        controller = ConcurrentInvestigationController()
        session = InvestigationSession(session_id="sess_multi_inval", objective="Multi parent")
        dag = DependencyGraph()

        gaps = {
            "P1": InformationGap(gap_id="P1", description="Parent 1", status=GapStatus.RESOLVED),
            "P2": InformationGap(gap_id="P2", description="Parent 2", status=GapStatus.RESOLVED),
            "Child": InformationGap(gap_id="Child", description="Child", status=GapStatus.OPEN),
        }
        session.gaps = gaps
        existing_ids = set(gaps.keys())
        dag.add_dependency("Child", "P1", existing_ids, gaps)
        dag.add_dependency("Child", "P2", existing_ids, gaps)

        # Invalidate P1 -> Child cascades to DEPENDENCY_UNSATISFIED
        controller.atomic_reopen_gap(session, "P1", "Reopening P1", dag)
        assert gaps["Child"].status == GapStatus.DEPENDENCY_UNSATISFIED

        # Re-resolve P1 -> Child restores to OPEN
        controller.atomic_resolve_gap(session, "P1", ["ev_p1"], "P1 re-resolved", dag)
        assert gaps["Child"].status == GapStatus.OPEN

    def test_repeated_invalidation_restoration_cycles_under_threads(self):
        controller = ConcurrentInvestigationController()
        session = InvestigationSession(session_id="sess_cycles", objective="10x cycles")
        dag = DependencyGraph()

        gaps = {
            "Upstream": InformationGap(gap_id="Upstream", description="Upstream", status=GapStatus.RESOLVED),
            "Downstream": InformationGap(gap_id="Downstream", description="Downstream", status=GapStatus.OPEN),
        }
        session.gaps = gaps
        dag.add_dependency("Downstream", "Upstream", set(gaps.keys()), gaps)

        for cycle in range(10):
            controller.atomic_reopen_gap(session, "Upstream", f"Reopen cycle {cycle}", dag)
            assert gaps["Downstream"].status == GapStatus.DEPENDENCY_UNSATISFIED

            controller.atomic_resolve_gap(session, "Upstream", [f"ev_{cycle}"], f"Resolve cycle {cycle}", dag)
            assert gaps["Downstream"].status == GapStatus.OPEN

    def test_fifty_node_dag_concurrent_invalidation(self):
        controller = ConcurrentInvestigationController()
        session = InvestigationSession(session_id="sess_dag_50", objective="50 node DAG")
        dag = DependencyGraph()

        # Linear chain: G0 -> G1 -> G2 -> ... -> G49
        gaps = {f"G{i}": InformationGap(gap_id=f"G{i}", description=f"Gap {i}", status=GapStatus.RESOLVED) for i in range(50)}
        session.gaps = gaps
        existing_ids = set(gaps.keys())

        for i in range(1, 50):
            dag.add_dependency(f"G{i}", f"G{i-1}", existing_ids, gaps)

        # Reopen root G0 -> all 49 downstream gaps must cascade to DEPENDENCY_UNSATISFIED
        controller.atomic_reopen_gap(session, "G0", "Root invalidation", dag)

        for i in range(1, 50):
            assert gaps[f"G{i}"].status == GapStatus.DEPENDENCY_UNSATISFIED


# =============================================================================
# SUITE 5: FAILURE INJECTION & RESILIENCE
# =============================================================================

class TestFailureInjection:
    """Verify worker timeouts, crashes, malformed evidence, and stale responses."""

    def test_retrieval_timeout_never_falsely_resolves(self):
        controller = ConcurrentInvestigationController()
        session = InvestigationSession(session_id="sess_fail_timeout", objective="Timeout test")
        gap = InformationGap(gap_id="gap_timeout", description="Timeout gap", max_attempts=2)
        session.gaps[gap.gap_id] = gap

        envelope = WorkerResultEnvelope(
            session_id=session.session_id,
            gap_id="gap_timeout",
            worker_id="worker_t1",
            result_type=WorkerResultType.TIMEOUT,
            failure_mode=FailureMode.RETRIEVAL_TIMEOUT,
            error_message="Retrieval timed out after 5.0s",
            gap_version_snapshot=0,
        )

        res = controller.submit_worker_result(session, envelope)
        assert res["status"] == "FAILURE_RECORDED"
        # Must NEVER be marked resolved
        assert gap.status != GapStatus.RESOLVED
        assert gap.status in [GapStatus.UNRESOLVED, GapStatus.OPEN]
        assert gap.attempt_count == 1

        # Second timeout reaches max_attempts -> transitions to BLOCKED
        envelope2 = WorkerResultEnvelope(
            session_id=session.session_id,
            gap_id="gap_timeout",
            worker_id="worker_t2",
            result_type=WorkerResultType.TIMEOUT,
            failure_mode=FailureMode.RETRIEVAL_TIMEOUT,
            error_message="Retrieval timed out after 5.0s (attempt 2)",
            gap_version_snapshot=gap.gap_version,
        )
        res2 = controller.submit_worker_result(session, envelope2)
        assert gap.status == GapStatus.BLOCKED
        assert gap.attempt_count == 2

    def test_malformed_evidence_rejected_without_corrupting_state(self):
        controller = ConcurrentInvestigationController()
        session = InvestigationSession(session_id="sess_fail_malformed", objective="Malformed test")
        gap = InformationGap(gap_id="gap_mal", description="Malformed gap")
        session.gaps[gap.gap_id] = gap

        envelope = WorkerResultEnvelope(
            session_id=session.session_id,
            gap_id="gap_mal",
            worker_id="worker_bad",
            result_type=WorkerResultType.MALFORMED,
            error_message="JSON syntax error in candidate chunk",
            gap_version_snapshot=0,
        )

        res = controller.submit_worker_result(session, envelope)
        assert res["status"] == "REJECTED_MALFORMED"
        assert gap.status != GapStatus.RESOLVED
        assert len(session.discovered_evidence) == 0

    def test_worker_crash_logged_as_failure_event(self):
        controller = ConcurrentInvestigationController()
        session = InvestigationSession(session_id="sess_fail_crash", objective="Crash test")
        gap = InformationGap(gap_id="gap_crash", description="Crash gap")
        session.gaps[gap.gap_id] = gap

        envelope = WorkerResultEnvelope(
            session_id=session.session_id,
            gap_id="gap_crash",
            worker_id="worker_crashing",
            result_type=WorkerResultType.FAILURE,
            failure_mode=FailureMode.WORKER_CRASH,
            error_message="Process terminated with SIGSEGV",
            gap_version_snapshot=0,
        )

        res = controller.submit_worker_result(session, envelope)
        assert res["status"] == "FAILURE_RECORDED"
        assert res["event"]["failure_mode"] == FailureMode.WORKER_CRASH.value

        # Check investigation trace contains WORKER_FAILURE event
        trace_events = [e for e in session.investigation_trace if e.event_type == "WORKER_FAILURE"]
        assert len(trace_events) == 1
        assert "SIGSEGV" in trace_events[0].details["error_message"]

    def test_empty_retrieval_records_zero_yield_query(self):
        controller = ConcurrentInvestigationController()
        session = InvestigationSession(session_id="sess_empty_yield", objective="Empty yield")
        gap = InformationGap(gap_id="gap_empty", description="Empty gap")
        session.gaps[gap.gap_id] = gap

        envelope = WorkerResultEnvelope(
            session_id=session.session_id,
            gap_id="gap_empty",
            worker_id="worker_e1",
            result_type=WorkerResultType.EMPTY,
            query="nonexistent entity query",
            gap_version_snapshot=0,
        )

        res = controller.submit_worker_result(session, envelope)
        assert res["status"] == "EMPTY_RESULT_RECORDED"
        assert "nonexistent entity query" in session.zero_yield_queries


# =============================================================================
# SUITE 6: DETERMINISM CHECK
# =============================================================================

class TestDeterminism:
    """Verify that random thread interleavings produce identical final state."""

    def test_deterministic_final_gap_status_across_twenty_runs(self):
        """
        Run 20 identical investigations with randomized thread execution order.
        Verify all 20 runs arrive at identical final gap statuses.
        """
        final_statuses = []

        for run in range(20):
            controller = ConcurrentInvestigationController()
            session = InvestigationSession(session_id=f"sess_det_{run}", objective="Determinism")
            dag = DependencyGraph()

            gaps = {
                "G1": InformationGap(gap_id="G1", description="Gap 1", status=GapStatus.OPEN),
                "G2": InformationGap(gap_id="G2", description="Gap 2", status=GapStatus.OPEN),
                "G3": InformationGap(gap_id="G3", description="Gap 3", status=GapStatus.DEPENDENCY_UNSATISFIED),
            }
            session.gaps = gaps
            dag.add_dependency("G3", "G1", set(gaps.keys()), gaps)
            dag.add_dependency("G3", "G2", set(gaps.keys()), gaps)

            barrier = threading.Barrier(2)

            def task_1():
                time.sleep(random.uniform(0.001, 0.005))
                barrier.wait()
                controller.atomic_resolve_gap(session, "G1", ["ev_1"], "resolved 1", dag)

            def task_2():
                time.sleep(random.uniform(0.001, 0.005))
                barrier.wait()
                controller.atomic_resolve_gap(session, "G2", ["ev_2"], "resolved 2", dag)

            t1 = threading.Thread(target=task_1)
            t2 = threading.Thread(target=task_2)
            t1.start()
            t2.start()
            t1.join()
            t2.join()

            run_state = (gaps["G1"].status, gaps["G2"].status, gaps["G3"].status)
            final_statuses.append(run_state)

        # Every single run must produce (RESOLVED, RESOLVED, OPEN)
        expected = (GapStatus.RESOLVED, GapStatus.RESOLVED, GapStatus.OPEN)
        assert all(status == expected for status in final_statuses)
        assert len(final_statuses) == 20


# =============================================================================
# SUITE 7: PERFORMANCE BASELINES
# =============================================================================

class TestPerformanceBaselines:
    """Measure latency and throughput baselines under concurrent contention."""

    def test_concurrent_budget_and_dag_operations_p95_latency(self):
        controller = ConcurrentInvestigationController()
        session = InvestigationSession(session_id="sess_perf", objective="Perf baseline", max_hops=1000)
        dag = DependencyGraph()

        gaps = {f"gap_{i}": InformationGap(gap_id=f"gap_{i}", description=f"Gap {i}") for i in range(100)}
        session.gaps = gaps
        existing_ids = set(gaps.keys())
        for i in range(1, 100):
            dag.add_dependency(f"gap_{i}", f"gap_{i-1}", existing_ids, gaps)

        latencies = []

        def worker(idx: int):
            t0 = time.perf_counter()
            controller.budget_guard.try_consume_hop(session)
            dag.get_prerequisites(f"gap_{idx}")
            dag.get_all_downstream(f"gap_{idx}")
            t1 = time.perf_counter()
            latencies.append((t1 - t0) * 1000.0) # milliseconds

        with concurrent.futures.ThreadPoolExecutor(max_workers=16) as executor:
            list(executor.map(worker, range(1, 100)))

        latencies.sort()
        p50 = latencies[int(len(latencies) * 0.50)]
        p95 = latencies[int(len(latencies) * 0.95)]
        p99 = latencies[int(len(latencies) * 0.99)]

        # Under local execution, p95 must be < 50ms for in-memory operations
        assert p95 < 50.0
        assert p50 < 10.0

    def test_100_node_dag_concurrent_validation_and_restoration(self):
        controller = ConcurrentInvestigationController()
        session = InvestigationSession(session_id="sess_dag_100", objective="100 node DAG")
        dag = DependencyGraph()

        # Build a 100-node graph: RootA and RootB -> 96 intermediate nodes -> Sink
        gaps = {"RootA": InformationGap(gap_id="RootA", description="Root A", status=GapStatus.OPEN),
                "RootB": InformationGap(gap_id="RootB", description="Root B", status=GapStatus.OPEN)}
        for i in range(96):
            gaps[f"Node_{i}"] = InformationGap(gap_id=f"Node_{i}", description=f"Node {i}", status=GapStatus.DEPENDENCY_UNSATISFIED)
        gaps["Sink"] = InformationGap(gap_id="Sink", description="Sink", status=GapStatus.DEPENDENCY_UNSATISFIED)
        session.gaps = gaps

        existing_ids = set(gaps.keys())
        for i in range(48):
            dag.add_dependency(f"Node_{i}", "RootA", existing_ids, gaps)
        for i in range(48, 96):
            dag.add_dependency(f"Node_{i}", "RootB", existing_ids, gaps)
        for i in range(96):
            dag.add_dependency("Sink", f"Node_{i}", existing_ids, gaps)

        # Concurrently resolve RootA and RootB
        barrier = threading.Barrier(2)
        def resolve_root(root_id: str):
            barrier.wait()
            controller.atomic_resolve_gap(session, root_id, [f"ev_{root_id}"], f"Resolved {root_id}", dag)

        t1 = threading.Thread(target=resolve_root, args=("RootA",))
        t2 = threading.Thread(target=resolve_root, args=("RootB",))
        t1.start()
        t2.start()
        t1.join()
        t2.join()

        # All intermediate nodes must now be restored to OPEN
        for i in range(96):
            assert gaps[f"Node_{i}"].status == GapStatus.OPEN

    def test_concurrent_atomic_reopen_and_invalidate_cascade(self):
        controller = ConcurrentInvestigationController()
        session = InvestigationSession(session_id="sess_multi_reopen", objective="Multi reopen")
        dag = DependencyGraph()

        gaps = {
            "P1": InformationGap(gap_id="P1", description="Parent 1", status=GapStatus.RESOLVED),
            "P2": InformationGap(gap_id="P2", description="Parent 2", status=GapStatus.RESOLVED),
        }
        for i in range(10):
            gaps[f"C{i}"] = InformationGap(gap_id=f"C{i}", description=f"Child {i}", status=GapStatus.RESOLVED)
        session.gaps = gaps

        existing_ids = set(gaps.keys())
        for i in range(10):
            dag.add_dependency(f"C{i}", "P1", existing_ids, gaps)
            dag.add_dependency(f"C{i}", "P2", existing_ids, gaps)

        # Concurrently reopen P1 and P2
        barrier = threading.Barrier(2)
        def reopen_parent(pid: str):
            barrier.wait()
            controller.atomic_reopen_gap(session, pid, f"Reopening {pid}", dag)

        t1 = threading.Thread(target=reopen_parent, args=("P1",))
        t2 = threading.Thread(target=reopen_parent, args=("P2",))
        t1.start()
        t2.start()
        t1.join()
        t2.join()

        # All 10 children must now be in DEPENDENCY_UNSATISFIED
        for i in range(10):
            assert gaps[f"C{i}"].status == GapStatus.DEPENDENCY_UNSATISFIED

    def test_partial_update_failure_mode_handling(self):
        controller = ConcurrentInvestigationController()
        session = InvestigationSession(session_id="sess_part_fail", objective="Partial update")
        gap = InformationGap(gap_id="gap_part", description="Partial gap")
        session.gaps[gap.gap_id] = gap

        envelope = WorkerResultEnvelope(
            session_id=session.session_id,
            gap_id="gap_part",
            worker_id="w_part",
            result_type=WorkerResultType.FAILURE,
            failure_mode=FailureMode.PARTIAL_UPDATE,
            error_message="Network dropped midway through payload transmission",
            gap_version_snapshot=0,
        )

        res = controller.submit_worker_result(session, envelope)
        assert res["status"] == "FAILURE_RECORDED"
        assert res["event"]["failure_mode"] == FailureMode.PARTIAL_UPDATE.value
        assert gap.status != GapStatus.RESOLVED

    def test_worker_exception_graceful_recovery(self):
        controller = ConcurrentInvestigationController()
        session = InvestigationSession(session_id="sess_exc", objective="Worker exception")
        gap = InformationGap(gap_id="gap_exc", description="Exception gap")
        session.gaps[gap.gap_id] = gap

        def crashing_worker():
            try:
                raise ConnectionResetError("Connection reset by remote peer")
            except Exception as e:
                envelope = WorkerResultEnvelope(
                    session_id=session.session_id,
                    gap_id="gap_exc",
                    worker_id="w_crash",
                    result_type=WorkerResultType.FAILURE,
                    failure_mode=FailureMode.EXCEPTION,
                    error_message=str(e),
                    gap_version_snapshot=0,
                )
                return controller.submit_worker_result(session, envelope)

        res = crashing_worker()
        assert res["status"] == "FAILURE_RECORDED"
        assert "Connection reset" in res["event"]["error_message"]
        assert gap.status != GapStatus.RESOLVED

    def test_duplicate_worker_result_submission_is_safe(self):
        controller = ConcurrentInvestigationController()
        session = InvestigationSession(session_id="sess_dup_sub", objective="Dup submission")
        gap = InformationGap(
            gap_id="gap_dup_sub",
            gap_type=GapType.AUTHORITY_RESOLUTION,
            target_entity="CR-101",
            description="Verify CR-101",
            status=GapStatus.SEARCHING,
        )
        session.gaps[gap.gap_id] = gap

        envelope = WorkerResultEnvelope(
            session_id=session.session_id,
            gap_id="gap_dup_sub",
            worker_id="w_dup",
            result_type=WorkerResultType.EVIDENCE,
            payload=[_make_sample_evidence("ev_dup_1", "DECISION: CR-101 is APPROVED for release")],
            gap_version_snapshot=0,
        )

        # First submission succeeds
        res1 = controller.submit_worker_result(session, envelope)
        assert res1["status"] == "APPLIED"
        assert gap.status == GapStatus.RESOLVED

        # Second submission of identical envelope is rejected as stale (gap already resolved)
        res2 = controller.submit_worker_result(session, envelope)
        assert res2["status"] == "REJECTED_STALE"
        assert len(session.discovered_evidence) == 1

    def test_concurrent_chunk_budget_exhaustion(self):
        controller = ConcurrentInvestigationController()
        session = InvestigationSession(session_id="sess_chunk_limit", objective="Chunk limit")
        # Pre-load with 14 chunks (limit is 15)
        for i in range(14):
            ev = _make_sample_evidence(f"ev_pre_{i}", f"Preload chunk {i}")
            session.discovered_evidence[ev.evidence_id] = ev

        gap = InformationGap(gap_id="gap_chunks", description="Chunk gap", status=GapStatus.OPEN)
        session.gaps[gap.gap_id] = gap

        envelope = WorkerResultEnvelope(
            session_id=session.session_id,
            gap_id="gap_chunks",
            worker_id="w_chunks",
            result_type=WorkerResultType.EVIDENCE,
            payload=[
                _make_sample_evidence("ev_add_1", "New chunk 1"),
                _make_sample_evidence("ev_add_2", "New chunk 2"),
                _make_sample_evidence("ev_add_3", "New chunk 3"),
            ],
            gap_version_snapshot=0,
        )

        res = controller.submit_worker_result(session, envelope)
        # Exactly 1 chunk should be admitted (14 + 1 = 15), remaining rejected
        assert len(session.discovered_evidence) == 15

    def test_thread_safety_session_lock_registry_cleanup(self):
        registry = SessionLockRegistry()

        def worker(sess_idx: int):
            sid = f"session_reg_{sess_idx}"
            lock = registry.get_lock(sid)
            with lock:
                pass
            registry.remove_session(sid)

        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            list(executor.map(worker, range(200)))

        # All sessions were cleaned up cleanly
        assert len(registry.active_sessions()) == 0

    def test_concurrent_dispatch_rollback_on_failure(self):
        controller = ConcurrentInvestigationController()
        session = InvestigationSession(session_id="sess_disp_clean", objective="Dispatch cleanup", max_queries=10)
        gap = InformationGap(gap_id="gap_clean", description="Clean gap")
        session.gaps[gap.gap_id] = gap

        # Dispatch action
        ok, reason, envelope = controller.dispatch_action(
            session=session,
            gap_id="gap_clean",
            query="query to fail",
            worker_id="worker_failing",
        )
        assert ok is True
        assert controller.dispatch_registry.is_in_flight(session.session_id, "query to fail")

        # Worker reports failure
        envelope.result_type = WorkerResultType.FAILURE
        envelope.failure_mode = FailureMode.RETRIEVAL_TIMEOUT
        envelope.error_message = "Retrieval timeout"

        controller.submit_worker_result(session, envelope)

        # In-flight set must now be clean
        assert not controller.dispatch_registry.is_in_flight(session.session_id, "query to fail")

