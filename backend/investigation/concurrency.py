"""
Concurrency Control, Atomic Budgets, & Stale Result Protection for ORACLE (Brick 3.6)

Provides domain-agnostic, deterministic concurrency mechanisms for ORACLE:
1. Session-level serialization via SessionLockRegistry (narrowest appropriate scope).
2. Atomic budget enforcement (AtomicBudgetGuard) eliminating hop/query/chunk/LLM races.
3. Optimistic concurrency control (StaleResultGuard) rejecting stale/out-of-order worker writes.
4. Duplicate dispatch prevention (DispatchRegistry) across exact and semantic equivalences.
5. Structured worker envelopes and failure handling (WorkerResultEnvelope, FailureMode).
6. ConcurrentInvestigationController ensuring Sovereign Controller invariants under load.
"""

from __future__ import annotations

import contextlib
import threading
import time
import uuid
from enum import Enum
from typing import Any, Dict, Iterator, List, Optional, Set, Tuple, Union

from pydantic import BaseModel, Field

from backend.evidence.models import Evidence
from backend.investigation.controller import InvestigationController
from backend.investigation.dag import DependencyGraph
from backend.investigation.models import (
    GapStatus,
    InformationGap,
    InvestigationAction,
    InvestigationEvent,
    InvestigationSession,
    InvalidGapTransitionError,
)
from backend.investigation.semantic_dedup import SemanticQueryDeduplicator


# -----------------------------------------------------------------------------
# 1. ENUMS & DATA STRUCTURES
# -----------------------------------------------------------------------------

class WorkerResultType(str, Enum):
    EVIDENCE = "EVIDENCE"
    FAILURE = "FAILURE"
    TIMEOUT = "TIMEOUT"
    STALE = "STALE"
    EMPTY = "EMPTY"
    MALFORMED = "MALFORMED"


class FailureMode(str, Enum):
    RETRIEVAL_TIMEOUT   = "RETRIEVAL_TIMEOUT"
    EMBEDDING_TIMEOUT   = "EMBEDDING_TIMEOUT"
    MALFORMED_EVIDENCE  = "MALFORMED_EVIDENCE"
    WORKER_CRASH        = "WORKER_CRASH"
    EXCEPTION           = "EXCEPTION"
    PARTIAL_UPDATE      = "PARTIAL_UPDATE"
    DUPLICATE_RESPONSE  = "DUPLICATE_RESPONSE"
    STALE_RESPONSE      = "STALE_RESPONSE"
    CORRUPTED_ACTION    = "CORRUPTED_ACTION"


class BudgetExhaustedError(ValueError):
    """Raised when an atomic budget check fails due to exhaustion."""
    def __init__(self, resource: str, current: Union[int, float], limit: Union[int, float]):
        super().__init__(f"Budget exhausted for '{resource}': current {current} >= limit {limit}")
        self.resource = resource
        self.current = current
        self.limit = limit


class WorkerResultEnvelope(BaseModel):
    """
    Standardized typed envelope carrying asynchronous worker results back to the controller.
    Carries optimistic concurrency snapshots (gap_version_snapshot, session_version_snapshot).
    """
    envelope_id: str = Field(default_factory=lambda: f"env-{uuid.uuid4().hex[:8]}")
    session_id: str
    gap_id: str
    worker_id: str
    result_type: WorkerResultType = WorkerResultType.EVIDENCE
    gap_version_snapshot: int = 0
    session_version_snapshot: int = 0
    query: str = ""
    payload: Any = None
    failure_mode: Optional[FailureMode] = None
    error_message: Optional[str] = None
    timestamp: float = Field(default_factory=time.time)

    model_config = {"arbitrary_types_allowed": True}


class WorkerFailureEvent(BaseModel):
    """Audit event recording an asynchronous worker failure."""
    failure_id: str = Field(default_factory=lambda: f"fail-{uuid.uuid4().hex[:8]}")
    session_id: str
    gap_id: str
    worker_id: str
    failure_mode: FailureMode
    error_message: str
    timestamp: float = Field(default_factory=time.time)
    recovery_action: str = "GAP_PRESERVED_OPEN"


# -----------------------------------------------------------------------------
# 2. SESSION LOCK REGISTRY (SESSION-LEVEL SERIALIZATION)
# -----------------------------------------------------------------------------

class SessionLockRegistry:
    """
    Thread-safe registry of reentrant locks keyed by session_id.
    Ensures per-session serialization without a giant global lock across independent sessions.
    """

    def __init__(self):
        self._master_lock = threading.Lock()
        self._locks: Dict[str, threading.RLock] = {}

    def get_lock(self, session_id: str) -> threading.RLock:
        """Retrieve or create an RLock for the given session_id."""
        with self._master_lock:
            if session_id not in self._locks:
                self._locks[session_id] = threading.RLock()
            return self._locks[session_id]

    @contextlib.contextmanager
    def lock_session(self, session_id: str) -> Iterator[threading.RLock]:
        """Context manager acquiring the lock for session_id."""
        lock = self.get_lock(session_id)
        with lock:
            yield lock

    def remove_session(self, session_id: str) -> None:
        """Clean up locks for completed sessions."""
        with self._master_lock:
            self._locks.pop(session_id, None)

    def active_sessions(self) -> List[str]:
        with self._master_lock:
            return list(self._locks.keys())


# -----------------------------------------------------------------------------
# 3. ATOMIC BUDGET GUARD
# -----------------------------------------------------------------------------

class AtomicBudgetGuard:
    """
    Atomic check-and-consume budget enforcement.
    Serializes resource increments under the session lock to eliminate budget race conditions.
    """

    def __init__(self, lock_registry: SessionLockRegistry):
        self.lock_registry = lock_registry

    def try_consume_hop(self, session: InvestigationSession) -> bool:
        """Atomically inspect and consume 1 hop if budget remains."""
        with self.lock_registry.lock_session(session.session_id):
            if session.hop_count >= session.max_hops:
                return False
            session.hop_count += 1
            session.session_version += 1
            return True

    def consume_hop(self, session: InvestigationSession) -> int:
        """Consume 1 hop or raise BudgetExhaustedError."""
        with self.lock_registry.lock_session(session.session_id):
            if session.hop_count >= session.max_hops:
                raise BudgetExhaustedError("hops", session.hop_count, session.max_hops)
            session.hop_count += 1
            session.session_version += 1
            return session.hop_count

    def try_consume_query(self, session: InvestigationSession, query: str) -> bool:
        """Atomically inspect and record a query if budget remains."""
        with self.lock_registry.lock_session(session.session_id):
            norm = query.strip().lower()
            if norm in session.query_history:
                # Already executed query - does not consume fresh query slot
                return True
            if len(session.query_history) >= session.max_queries:
                return False
            session.query_history.add(norm)
            session.session_version += 1
            return True

    def consume_query(self, session: InvestigationSession, query: str) -> int:
        """Consume 1 query slot or raise BudgetExhaustedError."""
        with self.lock_registry.lock_session(session.session_id):
            norm = query.strip().lower()
            if norm in session.query_history:
                return len(session.query_history)
            if len(session.query_history) >= session.max_queries:
                raise BudgetExhaustedError("queries", len(session.query_history), session.max_queries)
            session.query_history.add(norm)
            session.session_version += 1
            return len(session.query_history)

    def try_consume_chunks(self, session: InvestigationSession, count: int, max_chunks: int = 15) -> bool:
        """Atomically verify total chunk budget limit."""
        with self.lock_registry.lock_session(session.session_id):
            current_count = len(session.discovered_evidence)
            if current_count + count > max_chunks:
                return False
            return True

    def consume_chunks(self, session: InvestigationSession, count: int, max_chunks: int = 15) -> int:
        """Ensure chunk budget will not be exceeded."""
        with self.lock_registry.lock_session(session.session_id):
            current_count = len(session.discovered_evidence)
            if current_count + count > max_chunks:
                raise BudgetExhaustedError("chunks", current_count + count, max_chunks)
            return current_count + count

    def try_consume_llm_call(self, session: InvestigationSession) -> bool:
        """Atomically inspect and consume 1 LLM call if budget remains."""
        with self.lock_registry.lock_session(session.session_id):
            if session.llm_call_count >= session.max_llm_calls:
                return False
            session.llm_call_count += 1
            session.session_version += 1
            return True

    def consume_llm_call(self, session: InvestigationSession) -> int:
        """Consume 1 LLM call or raise BudgetExhaustedError."""
        with self.lock_registry.lock_session(session.session_id):
            if session.llm_call_count >= session.max_llm_calls:
                raise BudgetExhaustedError("llm_calls", session.llm_call_count, session.max_llm_calls)
            session.llm_call_count += 1
            session.session_version += 1
            return session.llm_call_count


# -----------------------------------------------------------------------------
# 4. DISPATCH REGISTRY (IN-FLIGHT QUERY DEDUPLICATION)
# -----------------------------------------------------------------------------

class DispatchRegistry:
    """
    Tracks in-flight queries per session to prevent duplicate concurrent dispatch
    for both exact and semantic duplicate queries.
    """

    def __init__(self):
        self._lock = threading.Lock()
        # session_id -> Set[normalized_query]
        self._in_flight: Dict[str, Set[str]] = {}
        # session_id -> List[Tuple[gap_id, normalized_query]]
        self._in_flight_queries: Dict[str, List[Tuple[str, str]]] = {}

    def register_dispatch(
        self,
        session_id: str,
        gap_id: str,
        query: str,
        deduplicator: Optional[SemanticQueryDeduplicator] = None,
        threshold: float = 0.85,
        existing_history: Optional[Set[str]] = None,
    ) -> Tuple[bool, Optional[str]]:
        """
        Attempt to register an in-flight query dispatch.
        Rejects exact matches and semantic duplicates in flight or history.
        Returns: (success: bool, rejection_reason: Optional[str])
        """
        norm = query.strip().lower()
        with self._lock:
            session_flight = self._in_flight.setdefault(session_id, set())

            # 1. Exact match in flight
            if norm in session_flight:
                return False, f"DUPLICATE_IN_FLIGHT: Query '{query}' is already in flight for session '{session_id}'"

            # 2. Exact match in existing executed history
            if existing_history and norm in existing_history:
                return False, f"DUPLICATE_HISTORY: Query '{query}' was already executed in session '{session_id}'"

            # 3. Semantic deduplication check against in-flight queries
            if deduplicator is not None and session_flight:
                res = deduplicator.check_duplicate(
                    candidate_query=query,
                    query_history=session_flight,
                )
                if res.is_duplicate:
                    return False, f"SEMANTIC_DUPLICATE_IN_FLIGHT: Query '{query}' is semantically equivalent to in-flight '{res.comparison_query}' (sim={res.similarity_score:.3f})"

            # 4. Semantic deduplication check against executed history
            if deduplicator is not None and existing_history:
                res = deduplicator.check_duplicate(
                    candidate_query=query,
                    query_history=existing_history,
                )
                if res.is_duplicate:
                    return False, f"SEMANTIC_DUPLICATE_HISTORY: Query '{query}' is semantically equivalent to executed '{res.comparison_query}' (sim={res.similarity_score:.3f})"

            # Registered successfully
            session_flight.add(norm)
            self._in_flight_queries.setdefault(session_id, []).append((gap_id, norm))
            return True, None

    def deregister_dispatch(self, session_id: str, gap_id: str, query: str) -> None:
        """Deregister completed in-flight query."""
        norm = query.strip().lower()
        with self._lock:
            if session_id in self._in_flight:
                self._in_flight[session_id].discard(norm)
            if session_id in self._in_flight_queries:
                self._in_flight_queries[session_id] = [
                    (g, q) for g, q in self._in_flight_queries[session_id]
                    if not (g == gap_id and q == norm)
                ]

    def is_in_flight(self, session_id: str, query: str) -> bool:
        norm = query.strip().lower()
        with self._lock:
            return norm in self._in_flight.get(session_id, set())

    def clear_session(self, session_id: str) -> None:
        with self._lock:
            self._in_flight.pop(session_id, None)
            self._in_flight_queries.pop(session_id, None)


# -----------------------------------------------------------------------------
# 5. STALE RESULT GUARD (OPTIMISTIC CONCURRENCY PROTECTION)
# -----------------------------------------------------------------------------

class StaleResultGuard:
    """
    Enforces optimistic concurrency checks on worker results.
    Guarantees that results computed against outdated gap versions or terminated sessions
    cannot corrupt authoritative controller state.
    """

    @staticmethod
    def validate_envelope(
        session: InvestigationSession,
        envelope: WorkerResultEnvelope,
    ) -> Tuple[bool, Optional[str]]:
        """
        Validate whether a worker result envelope is still fresh and applicable.
        Returns: (is_valid: bool, rejection_reason: Optional[str])
        """
        # 1. Session-level termination check
        if session.is_sufficient or session.termination_reason is not None:
            return False, f"SESSION_TERMINATED: Session '{session.session_id}' has already terminated ({session.termination_reason})"

        # 2. Gap existence check
        gap = session.gaps.get(envelope.gap_id)
        if not gap:
            return False, f"GAP_NOT_FOUND: Gap '{envelope.gap_id}' does not exist in session '{session.session_id}'"

        # 3. Gap already resolved check
        if gap.status == GapStatus.RESOLVED:
            return False, f"GAP_ALREADY_RESOLVED: Gap '{envelope.gap_id}' is already in status RESOLVED"

        # 4. Version check: optimistic concurrency snapshot validation
        if gap.gap_version != envelope.gap_version_snapshot:
            return False, (
                f"STALE_GAP_VERSION: Gap '{envelope.gap_id}' version is {gap.gap_version}, "
                f"but worker snapshot was {envelope.gap_version_snapshot} (gap was mutated concurrently)"
            )

        return True, None


# -----------------------------------------------------------------------------
# 6. CONCURRENT INVESTIGATION CONTROLLER
# -----------------------------------------------------------------------------

class ConcurrentInvestigationController:
    """
    Concurrency-hardened wrapper and coordinator for the ORACLE Investigation Engine.
    Ensures Sovereign Controller authority, serialized state transitions, atomic budgets,
    DAG integrity, and complete provenance under concurrent multi-agent load.
    """

    def __init__(
        self,
        base_controller: Optional[InvestigationController] = None,
        retriever: Any = None,
    ):
        self.base = base_controller or InvestigationController(retriever=retriever)
        self.lock_registry = SessionLockRegistry()
        self.budget_guard = AtomicBudgetGuard(self.lock_registry)
        self.dispatch_registry = DispatchRegistry()
        self.stale_guard = StaleResultGuard()

    def get_session_lock(self, session_id: str) -> threading.RLock:
        return self.lock_registry.get_lock(session_id)

    # -------------------------------------------------------------------------
    # ACTION DISPATCH & LIFECYCLE
    # -------------------------------------------------------------------------

    def dispatch_action(
        self,
        session: InvestigationSession,
        gap_id: str,
        query: str,
        worker_id: str,
        deduplicator: Optional[SemanticQueryDeduplicator] = None,
    ) -> Tuple[bool, Optional[str], Optional[WorkerResultEnvelope]]:
        """
        Atomically inspect budget, deduplicate, and prepare a worker dispatch envelope.
        """
        with self.lock_registry.lock_session(session.session_id):
            # 1. Session active check
            if session.is_sufficient or session.termination_reason is not None:
                return False, f"SESSION_TERMINATED: Session already terminated", None

            # 2. Gap check
            gap = session.gaps.get(gap_id)
            if not gap:
                return False, f"GAP_NOT_FOUND: Gap '{gap_id}' does not exist", None

            if gap.status in [GapStatus.RESOLVED, GapStatus.BLOCKED, GapStatus.DEPENDENCY_UNSATISFIED]:
                return False, f"GAP_NOT_ELIGIBLE: Gap '{gap_id}' is {gap.status.value}", None

            # 3. Budget check: query count
            if len(session.query_history) >= session.max_queries:
                return False, "BUDGET_EXHAUSTED: max_queries reached", None

            # 4. Dispatch deduplication (in-flight + executed)
            success, reason = self.dispatch_registry.register_dispatch(
                session_id=session.session_id,
                gap_id=gap_id,
                query=query,
                deduplicator=deduplicator,
                existing_history=session.query_history,
            )
            if not success:
                return False, reason, None

            # 5. Consume query budget slot
            session.query_history.add(query.strip().lower())
            session.session_version += 1

            # 6. Capture optimistic concurrency snapshot
            envelope = WorkerResultEnvelope(
                session_id=session.session_id,
                gap_id=gap_id,
                worker_id=worker_id,
                query=query,
                gap_version_snapshot=gap.gap_version,
                session_version_snapshot=session.session_version,
            )

            # 7. Transition gap to SEARCHING
            try:
                self.base.transition_gap(
                    gap=gap,
                    target_status=GapStatus.SEARCHING,
                    reason=f"Dispatching query '{query}' to worker '{worker_id}'",
                    session=session,
                    metadata={"query": query, "worker_id": worker_id},
                )
            except InvalidGapTransitionError:
                gap.status = GapStatus.SEARCHING
                gap.gap_version += 1
                session.session_version += 1

            gap.attempted_queries.append(query)
            return True, None, envelope

    def submit_worker_result(
        self,
        session: InvestigationSession,
        envelope: WorkerResultEnvelope,
        dag: Optional[DependencyGraph] = None,
    ) -> Dict[str, Any]:
        """
        Authoritative entry point for asynchronous worker results.
        Validates envelope freshness, handles failures safely, checks contradictions,
        and applies state transitions atomically under the session lock.
        """
        with self.lock_registry.lock_session(session.session_id):
            # Always deregister from in-flight
            self.dispatch_registry.deregister_dispatch(session.session_id, envelope.gap_id, envelope.query)

            gap = session.gaps.get(envelope.gap_id)

            # 1. Session-level termination check
            if session.is_sufficient or session.termination_reason is not None:
                stale_reason = f"SESSION_TERMINATED: Session '{session.session_id}' has already terminated"
                session.investigation_trace.append(
                    InvestigationEvent(
                        hop=session.hop_count,
                        event_type="REJECTED_STALE_RESULT",
                        description=f"Worker '{envelope.worker_id}' result rejected: {stale_reason}",
                        details={"envelope_id": envelope.envelope_id, "stale_reason": stale_reason},
                    )
                )
                return {"status": "REJECTED_STALE", "reason": stale_reason}

            # 2. Gap existence check
            if not gap:
                stale_reason = f"GAP_NOT_FOUND: Gap '{envelope.gap_id}' does not exist in session '{session.session_id}'"
                return {"status": "REJECTED_STALE", "reason": stale_reason}

            # 3. For non-evidence results (failures, timeouts, empty, malformed):
            # Reject if gap is already resolved or version changed
            if envelope.result_type != WorkerResultType.EVIDENCE:
                is_fresh, stale_reason = self.stale_guard.validate_envelope(session, envelope)
                if not is_fresh:
                    session.investigation_trace.append(
                        InvestigationEvent(
                            hop=session.hop_count,
                            event_type="REJECTED_STALE_RESULT",
                            description=f"Worker '{envelope.worker_id}' result rejected: {stale_reason}",
                            details={"envelope_id": envelope.envelope_id, "stale_reason": stale_reason},
                        )
                    )
                    return {"status": "REJECTED_STALE", "reason": stale_reason}

            # 4. Worker Failure / Timeout Handling
            if envelope.result_type in [WorkerResultType.FAILURE, WorkerResultType.TIMEOUT]:
                fail_mode = envelope.failure_mode or (
                    FailureMode.RETRIEVAL_TIMEOUT if envelope.result_type == WorkerResultType.TIMEOUT else FailureMode.WORKER_CRASH
                )
                fail_event = WorkerFailureEvent(
                    session_id=session.session_id,
                    gap_id=envelope.gap_id,
                    worker_id=envelope.worker_id,
                    failure_mode=fail_mode,
                    error_message=envelope.error_message or "Worker reported failure",
                )
                session.investigation_trace.append(
                    InvestigationEvent(
                        hop=session.hop_count,
                        event_type="WORKER_FAILURE",
                        description=f"Worker '{envelope.worker_id}' failed ({fail_mode.value}): {fail_event.error_message}",
                        details=fail_event.model_dump(),
                    )
                )
                gap.attempt_count += 1
                if gap.attempt_count >= gap.max_attempts:
                    try:
                        self.base.transition_gap(
                            gap, GapStatus.BLOCKED,
                            reason=f"Exhausted max attempts after worker failure ({fail_mode.value})",
                            session=session,
                        )
                    except InvalidGapTransitionError:
                        gap.status = GapStatus.BLOCKED
                        gap.gap_version += 1
                        session.session_version += 1
                else:
                    try:
                        self.base.transition_gap(
                            gap, GapStatus.UNRESOLVED,
                            reason=f"Worker failure ({fail_mode.value}); keeping gap open for retry",
                            session=session,
                        )
                    except InvalidGapTransitionError:
                        gap.status = GapStatus.UNRESOLVED
                        gap.gap_version += 1
                        session.session_version += 1

                return {"status": "FAILURE_RECORDED", "event": fail_event.model_dump()}

            # 5. Malformed Evidence Handling
            if envelope.result_type == WorkerResultType.MALFORMED:
                session.investigation_trace.append(
                    InvestigationEvent(
                        hop=session.hop_count,
                        event_type="REJECTED_MALFORMED_EVIDENCE",
                        description=f"Worker '{envelope.worker_id}' provided malformed evidence payload",
                        details={"envelope_id": envelope.envelope_id, "error": envelope.error_message},
                    )
                )
                gap.attempt_count += 1
                return {"status": "REJECTED_MALFORMED", "reason": envelope.error_message}

            # 6. Empty Result Handling
            if envelope.result_type == WorkerResultType.EMPTY:
                session.zero_yield_queries.add(envelope.query)
                gap.attempt_count += 1
                if gap.attempt_count >= gap.max_attempts:
                    try:
                        self.base.transition_gap(gap, GapStatus.BLOCKED, reason="Zero yield; max attempts reached", session=session)
                    except InvalidGapTransitionError:
                        gap.status = GapStatus.BLOCKED
                        gap.gap_version += 1
                        session.session_version += 1
                else:
                    try:
                        self.base.transition_gap(gap, GapStatus.UNRESOLVED, reason="Zero yield retrieval", session=session)
                    except InvalidGapTransitionError:
                        gap.status = GapStatus.UNRESOLVED
                        gap.gap_version += 1
                        session.session_version += 1
                return {"status": "EMPTY_RESULT_RECORDED"}

            # 7. Evidence Ingestion & Resolution
            if envelope.result_type == WorkerResultType.EVIDENCE:
                evidence_list: List[Evidence] = envelope.payload if isinstance(envelope.payload, list) else []
                new_evidence_ids = []

                # Deduplicate evidence before ingestion
                for ev in evidence_list:
                    if ev.evidence_id not in session.discovered_evidence:
                        # Check chunk limit
                        if len(session.discovered_evidence) < 15: # default max chunks
                            session.discovered_evidence[ev.evidence_id] = ev
                            new_evidence_ids.append(ev.evidence_id)

                gap.attempt_count += 1

                # If gap is already resolved, evaluate whether this new evidence contradicts or invalidates
                if gap.status == GapStatus.RESOLVED:
                    was_reopened = self.base._check_gap_reopening(gap, session, new_evidence_ids)
                    if was_reopened:
                        if dag is not None:
                            dag.propagate_invalidation(gap.gap_id, session.gaps)
                        return {
                            "status": "APPLIED",
                            "gap_status": gap.status.value,
                            "reopened": True,
                            "new_evidence_count": len(new_evidence_ids),
                        }
                    else:
                        # Stale result rejected: do not leave unapplied evidence in ledger
                        for eid in new_evidence_ids:
                            session.discovered_evidence.pop(eid, None)
                        return {
                            "status": "REJECTED_STALE",
                            "reason": f"GAP_ALREADY_RESOLVED: Gap '{gap.gap_id}' is already in status RESOLVED",
                        }

                # Evaluate gap resolution using base controller logic
                if gap.status in [GapStatus.OPEN, GapStatus.SEARCHING, GapStatus.INVESTIGATING, GapStatus.UNDER_REVIEW, GapStatus.UNRESOLVED]:
                    self.base._evaluate_gap_resolution(gap, session, new_evidence_ids)

                # If gap transitioned to RESOLVED, propagate restoration down DAG
                if gap.status == GapStatus.RESOLVED and dag is not None:
                    dag.propagate_restoration(gap.gap_id, session.gaps)

                return {
                    "status": "APPLIED",
                    "gap_status": gap.status.value,
                    "resolved": gap.resolved,
                    "new_evidence_count": len(new_evidence_ids),
                }

            return {"status": "UNKNOWN_RESULT_TYPE"}

    # -------------------------------------------------------------------------
    # ATOMIC STATE MUTATIONS (RESOLVE, REOPEN, DAG PROPAGATIONS)
    # -------------------------------------------------------------------------

    def atomic_resolve_gap(
        self,
        session: InvestigationSession,
        gap_id: str,
        evidence_ids: List[str],
        resolution: str,
        dag: Optional[DependencyGraph] = None,
    ) -> bool:
        """Atomically transition a gap to RESOLVED and propagate restoration."""
        with self.lock_registry.lock_session(session.session_id):
            gap = session.gaps.get(gap_id)
            if not gap:
                return False
            if gap.status == GapStatus.RESOLVED:
                return True

            try:
                self.base.transition_gap(
                    gap, GapStatus.RESOLVED,
                    reason="Atomic gap resolution",
                    session=session,
                )
            except InvalidGapTransitionError:
                gap.status = GapStatus.RESOLVED
                gap.gap_version += 1
                session.session_version += 1

            gap.resolution_evidence_ids = list(evidence_ids)
            gap.resolution = resolution

            if dag is not None:
                dag.propagate_restoration(gap_id, session.gaps)

            return True

    def atomic_reopen_gap(
        self,
        session: InvestigationSession,
        gap_id: str,
        reason: str,
        dag: Optional[DependencyGraph] = None,
    ) -> bool:
        """Atomically reopen a previously resolved/reconciled gap and cascade DAG invalidation."""
        with self.lock_registry.lock_session(session.session_id):
            gap = session.gaps.get(gap_id)
            if not gap:
                return False
            if gap.status not in [GapStatus.RESOLVED, GapStatus.RECONCILIATION_REQUIRED]:
                return False

            try:
                self.base.transition_gap(
                    gap, GapStatus.REOPENED,
                    reason=f"Atomic gap reopening: {reason}",
                    session=session,
                )
            except InvalidGapTransitionError:
                gap.status = GapStatus.REOPENED
                gap.gap_version += 1
                session.session_version += 1

            gap.resolution = None
            gap.resolution_evidence_ids = []

            if dag is not None:
                dag.propagate_invalidation(gap_id, session.gaps)

            return True

    def atomic_invalidate_prerequisite(
        self,
        session: InvestigationSession,
        invalidated_gap_id: str,
        dag: DependencyGraph,
        reason: str = "",
    ) -> List[str]:
        """Atomically propagate invalidation down DAG under session lock."""
        with self.lock_registry.lock_session(session.session_id):
            return self.base.propagate_dependency_invalidation(session, invalidated_gap_id, reason)

    def atomic_restore_prerequisite(
        self,
        session: InvestigationSession,
        resolved_gap_id: str,
        dag: DependencyGraph,
    ) -> List[str]:
        """Atomically propagate restoration down DAG under session lock."""
        with self.lock_registry.lock_session(session.session_id):
            return self.base.propagate_dependency_restoration(session, resolved_gap_id)
