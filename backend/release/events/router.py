"""
Enterprise Event Router & Ingestion Pipeline (Brick 4.3)

Orchestrates the complete event-driven intelligence flow:
Webhook Signature Verification
  ↓
Event Normalization
  ↓
Idempotency Check (Duplicate Suppression)
  ↓
Deterministic Entity Resolution
  ↓
Investigation Impact Analysis
  ↓
Evidence Lifecycle Invalidation (VALID -> STALE / SUPERSEDED)
  ↓
Evidence Graph Relationship Updates
  ↓
Targeted DAG Re-investigation
  ↓
Deterministic Decision Recalculation
  ↓
Decision Lineage & Change Explanation
  ↓
Notification & Governed Action Registration
"""

from __future__ import annotations

import json
import threading
import time
from typing import Any, Dict, List, Optional, Tuple

from backend.release.actions import GovernedActionExecutor
from backend.release.decision import ReleaseDecisionEngine
from backend.release.events.graph import EvidenceGraph, GraphEdgeType, GraphNodeType
from backend.release.events.idempotency import EventIdempotencyManager
from backend.release.events.impact import ImpactAnalysisResult, InvestigationImpactAnalyzer
from backend.release.events.lifecycle import EvidenceLifecycleManager, EvidenceState
from backend.release.events.lineage import DecisionLineageTracker
from backend.release.events.models import DecisionChangeEvent, EnterpriseEvent, EnterpriseEventType
from backend.release.events.normalizers import (
    EventNormalizer,
    GitHubEventNormalizer,
    JiraEventNormalizer,
    SecurityEventNormalizer,
)
from backend.release.events.resolver import DeterministicEntityResolver
from backend.release.events.security import WebhookSecurityValidator
from backend.release.investigation import ReleaseReadinessInvestigator
from backend.release.models import ReleaseAssessment, ReleaseCandidate


class IngestionReceipt(BaseModel if False else object):
    """Deliverable returned after processing an enterprise webhook/event."""
    def __init__(
        self,
        event_id: str,
        idempotency_key: str,
        is_duplicate: bool,
        affected_release_ids: List[str],
        impact_results: List[ImpactAnalysisResult],
        notifications: List[DecisionChangeEvent],
        status: str = "PROCESSED",
    ):
        self.event_id = event_id
        self.idempotency_key = idempotency_key
        self.is_duplicate = is_duplicate
        self.affected_release_ids = affected_release_ids
        self.impact_results = impact_results
        self.notifications = notifications
        self.status = status

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "idempotency_key": self.idempotency_key,
            "is_duplicate": self.is_duplicate,
            "affected_release_ids": self.affected_release_ids,
            "impact_results": [ir.model_dump() for ir in self.impact_results],
            "notifications": [n.model_dump() for n in self.notifications],
            "status": self.status,
        }


class EventRouter:
    """
    Central event ingestion and targeted re-investigation orchestrator.
    Thread-safe, sovereign, and resilient against burst loads.
    """

    def __init__(
        self,
        investigator: ReleaseReadinessInvestigator,
        decision_engine: ReleaseDecisionEngine,
        action_executor: GovernedActionExecutor,
        normalizers: Optional[List[EventNormalizer]] = None,
        security_validator: Optional[WebhookSecurityValidator] = None,
        idempotency_manager: Optional[EventIdempotencyManager] = None,
        entity_resolver: Optional[DeterministicEntityResolver] = None,
        impact_analyzer: Optional[InvestigationImpactAnalyzer] = None,
        lifecycle_manager: Optional[EvidenceLifecycleManager] = None,
        evidence_graph: Optional[EvidenceGraph] = None,
        lineage_tracker: Optional[DecisionLineageTracker] = None,
        store: Optional[Any] = None,
    ):
        self.investigator = investigator
        self.decision_engine = decision_engine
        self.action_executor = action_executor
        self.store = store

        self.normalizers = normalizers or [
            GitHubEventNormalizer(),
            JiraEventNormalizer(),
            SecurityEventNormalizer(),
        ]
        self.security_validator = security_validator or WebhookSecurityValidator()
        self.idempotency_manager = idempotency_manager or EventIdempotencyManager()
        self.entity_resolver = entity_resolver or DeterministicEntityResolver()
        self.impact_analyzer = impact_analyzer or InvestigationImpactAnalyzer()
        self.lifecycle_manager = lifecycle_manager or EvidenceLifecycleManager()
        self.evidence_graph = evidence_graph or EvidenceGraph()
        self.lineage_tracker = lineage_tracker or DecisionLineageTracker()

        # Wire action executor with store if available
        if self.store and hasattr(self.store, "actions") and hasattr(self.action_executor, "action_repo"):
            if not self.action_executor.action_repo:
                self.action_executor.action_repo = self.store.actions

        # Investigation state registry: release_id -> latest ReleaseAssessment
        self._assessments: Dict[str, ReleaseAssessment] = {}
        self._events_log: List[EnterpriseEvent] = []
        self._lock = threading.RLock()

    def register_candidate(self, candidate: ReleaseCandidate, initial_assessment: Optional[ReleaseAssessment] = None) -> None:
        """Register release candidate and initial assessment into entity resolver and graph."""
        with self._lock:
            self.entity_resolver.register_candidate(candidate)
            if self.store and hasattr(self.store, "entities"):
                self.store.entities.save_candidate(candidate)
            if initial_assessment:
                self._assessments[candidate.release_id] = initial_assessment
                if self.store and hasattr(self.store, "investigations"):
                    self.store.investigations.save_assessment(initial_assessment)
                if self.store and hasattr(self.store, "decisions"):
                    self.store.decisions.save_decision(initial_assessment.decision)

                # Graph node for Release
                self.evidence_graph.add_node(
                    node_id=candidate.release_id,
                    node_type=GraphNodeType.RELEASE,
                    properties={
                        "service_name": candidate.service_name,
                        "version": candidate.version,
                        "commit": candidate.commit,
                        "repository": candidate.repository,
                    },
                )

                # Graph node for Repository
                self.evidence_graph.add_node(
                    node_id=candidate.repository,
                    node_type=GraphNodeType.REPOSITORY,
                )
                self.evidence_graph.add_edge(
                    candidate.repository,
                    candidate.release_id,
                    GraphEdgeType.TARGETS,
                )

                # Graph node for Initial Decision
                self.evidence_graph.add_node(
                    node_id=f"dec-{candidate.release_id}",
                    node_type=GraphNodeType.DECISION,
                    properties={"outcome": initial_assessment.decision.outcome.value},
                )
                self.evidence_graph.add_edge(
                    candidate.release_id,
                    f"dec-{candidate.release_id}",
                    GraphEdgeType.GENERATED,
                )

                # Record baseline decision lineage
                self.lineage_tracker.record_decision(
                    release_id=candidate.release_id,
                    decision=initial_assessment.decision,
                )

    def get_assessment(self, release_id: str) -> Optional[ReleaseAssessment]:
        with self._lock:
            ass = self._assessments.get(release_id)
            if not ass and self.store and hasattr(self.store, "investigations"):
                ass = self.store.investigations.get_assessment(release_id)
                if ass:
                    self._assessments[release_id] = ass
            return ass

    def get_all_assessments(self) -> Dict[str, ReleaseAssessment]:
        with self._lock:
            if self.store and hasattr(self.store, "investigations"):
                db_assessments = self.store.investigations.get_all_assessments()
                db_assessments.update(self._assessments)
                return db_assessments
            return dict(self._assessments)

    def get_event_history(self, release_id: Optional[str] = None) -> List[EnterpriseEvent]:
        with self._lock:
            if not release_id:
                return list(self._events_log)
            return [e for e in self._events_log if e.release_id == release_id]

    def ingest_webhook(
        self,
        source: str,
        event_name: str,
        payload: Dict[str, Any],
        raw_body: Optional[bytes] = None,
        headers: Optional[Dict[str, str]] = None,
        secret: Optional[str] = None,
    ) -> IngestionReceipt:
        """
        Ingest raw webhook through security gates, normalization, idempotency, and targeted cascade.
        """
        headers = headers or {}
        raw_bytes = raw_body or json.dumps(payload).encode("utf-8")

        # 1. Webhook Security Verification
        if secret:
            if source.lower() in ("github", "github_actions"):
                sig = headers.get("x-hub-signature-256") or headers.get("X-Hub-Signature-256")
                self.security_validator.verify_github_signature(raw_bytes, sig, secret)
            elif source.lower() == "jira":
                sec_header = headers.get("x-atlassian-webhook-token") or headers.get("X-Atlassian-Webhook-Token") or headers.get("Authorization")
                self.security_validator.verify_jira_secret(sec_header, secret)

        # 2. Normalize Payload into EnterpriseEvent(s)
        normalizer = next((n for n in self.normalizers if n.can_handle(source, event_name, payload)), None)
        if not normalizer:
            raise ValueError(f"No registered normalizer capable of handling source '{source}', event '{event_name}'.")

        events = normalizer.normalize(source=source, event_name=event_name, payload=payload, headers=headers)
        if not events:
            return IngestionReceipt(
                event_id="none",
                idempotency_key="none",
                is_duplicate=False,
                affected_release_ids=[],
                impact_results=[],
                notifications=[],
                status="IGNORED_NO_RELEVANT_EVENT",
            )

        # Process primary event
        primary_evt = events[0]
        return self.process_event(primary_evt)

    def process_event(self, event: EnterpriseEvent, is_replay: bool = False) -> IngestionReceipt:
        """
        Core sovereign event processing method:
        Idempotency -> Resolution -> Impact Analysis -> Lifecycle -> Targeted Re-investigation -> Lineage.
        """
        with self._lock:
            self._events_log.append(event)
            if self.store and hasattr(self.store, "events") and not is_replay:
                self.store.events.append_event(event)

            # 1. Idempotency Check (DB-enforced or In-Memory)
            idempotency_key = self.idempotency_manager.compute_key(event)
            if self.store and hasattr(self.store, "idempotency") and not is_replay:
                is_new = self.store.idempotency.register_if_absent(
                    idempotency_key=idempotency_key,
                    event_id=event.event_id,
                    source=event.source,
                    source_event_id=event.source_event_id,
                    event_type=event.event_type.value if hasattr(event.event_type, "value") else str(event.event_type),
                )
            else:
                is_new, existing_rec = self.idempotency_manager.register_if_absent(event)

            if not is_new and not is_replay:
                # Duplicate suppression: return cached receipt without duplicate side-effects
                return IngestionReceipt(
                    event_id=event.event_id,
                    idempotency_key=idempotency_key,
                    is_duplicate=True,
                    affected_release_ids=[],
                    impact_results=[],
                    notifications=[],
                    status="DUPLICATE_SUPPRESSED",
                )

            # 2. Deterministic Entity Resolution
            affected_candidates = self.entity_resolver.resolve_affected_releases(event)
            affected_ids = [c.release_id for c in affected_candidates]

            impact_results: List[ImpactAnalysisResult] = []
            notifications: List[DecisionChangeEvent] = []

            # Add event node to EvidenceGraph
            self.evidence_graph.add_node(
                node_id=event.event_id,
                node_type=GraphNodeType.ACTION,
                properties={"event_type": event.event_type.value, "source": event.source},
            )

            # 3. Process Impact and Targeted Re-investigation per affected release
            for candidate in affected_candidates:
                # Link Event -> Release in EvidenceGraph
                self.evidence_graph.add_edge(
                    event.event_id,
                    candidate.release_id,
                    GraphEdgeType.AFFECTS,
                )

                # Get existing assessment
                prev_assessment = self.get_assessment(candidate.release_id)
                prev_inv = prev_assessment.get_investigation() if hasattr(prev_assessment, "get_investigation") else None
                if not prev_inv and prev_assessment:
                    # Construct minimal result container from assessment if needed
                    from backend.release.investigation import ReleaseInvestigationResult
                    prev_inv = ReleaseInvestigationResult(
                        candidate=candidate,
                        gaps=prev_assessment.gaps,
                        admitted_evidence=prev_assessment.discovered_evidence,
                    )

                # 4. Impact Analysis
                impact = self.impact_analyzer.analyze_impact(
                    event=event,
                    candidate=candidate,
                    previous_result=prev_inv,
                )
                impact_results.append(impact)

                # 5. Evidence Lifecycle Invalidation
                for ev_id in impact.invalidated_evidence_ids:
                    self.lifecycle_manager.mark_stale(
                        evidence_id=ev_id,
                        event_id=event.event_id,
                        reason=impact.reason,
                    )
                    # Mark edge in graph as inactive
                    self.evidence_graph.invalidate_edge(ev_id, candidate.release_id, GraphEdgeType.SUPPORTS)

                # Update candidate commit if CODE_PUSHED
                if event.event_type == EnterpriseEventType.CODE_PUSHED and event.commit:
                    candidate.commit = event.commit
                    self.evidence_graph.add_node(
                        node_id=event.commit,
                        node_type=GraphNodeType.COMMIT,
                        properties={"repository": candidate.repository},
                    )
                    self.evidence_graph.add_edge(
                        candidate.release_id,
                        event.commit,
                        GraphEdgeType.BASED_ON,
                    )

                # 6. Targeted Re-investigation
                if impact.requires_reinvestigation and prev_inv:
                    reinv_result = self.investigator.reinvestigate_targeted(
                        candidate=candidate,
                        previous_result=prev_inv,
                        affected_gap_ids=impact.affected_gap_ids,
                        invalidated_evidence_ids=impact.invalidated_evidence_ids,
                    )

                    # 7. Sovereign Decision Recalculation
                    new_decision = self.decision_engine.evaluate_decision(reinv_result)

                    # Register newly generated governed action proposals (suppressed during replay)
                    if not is_replay:
                        for action in new_decision.governed_actions:
                            self.action_executor.register_proposal(action)

                    # 8. Decision Lineage & Explainability
                    notif = self.lineage_tracker.record_decision(
                        release_id=candidate.release_id,
                        decision=new_decision,
                        trigger_event=event,
                        invalidated_evidence_ids=impact.invalidated_evidence_ids,
                    )
                    if notif:
                        notifications.append(notif)

                    # 9. Update Session Assessment
                    new_assessment = ReleaseAssessment(
                        candidate=candidate,
                        decision=new_decision,
                        discovered_evidence=reinv_result.admitted_evidence,
                        gaps=reinv_result.gaps,
                        contradictions=reinv_result.contradictions,
                        telemetry=reinv_result.telemetry,
                    )
                    self._assessments[candidate.release_id] = new_assessment

                    # Persist state if store is available
                    if self.store:
                        if hasattr(self.store, "investigations"):
                            self.store.investigations.save_investigation(reinv_result)
                        if hasattr(self.store, "decisions"):
                            self.store.decisions.save_decision(new_decision)
                        if notif and hasattr(self.store, "lineage"):
                            self.store.lineage.record_transition(candidate.release_id, notif)

                    # Update EvidenceGraph with new decision
                    dec_node_id = f"dec-{candidate.release_id}-{int(time.time()*1000)}"
                    self.evidence_graph.add_node(
                        node_id=dec_node_id,
                        node_type=GraphNodeType.DECISION,
                        properties={"outcome": new_decision.outcome.value},
                    )
                    self.evidence_graph.add_edge(
                        candidate.release_id,
                        dec_node_id,
                        GraphEdgeType.GENERATED,
                    )

            receipt = IngestionReceipt(
                event_id=event.event_id,
                idempotency_key=idempotency_key,
                is_duplicate=False,
                affected_release_ids=affected_ids,
                impact_results=impact_results,
                notifications=notifications,
                status="PROCESSED",
            )

            self.idempotency_manager.store_impact_result(idempotency_key, receipt.to_dict())
            return receipt

    def process_canonical_event(self, event: EnterpriseEvent, is_replay: bool = False) -> IngestionReceipt:
        """Alias for process_event to support replay engines."""
        return self.process_event(event, is_replay=is_replay)

    def handle_evidence_drift(self, release_id: str, expired_evidence_ids: List[str]) -> Optional[ReleaseAssessment]:
        """Trigger targeted DAG reinvestigation for evidence that expired due to TTL drift."""
        with self._lock:
            assessment = self.get_assessment(release_id)
            if not assessment:
                return None

            candidate = assessment.candidate
            from backend.release.investigation import ReleaseInvestigationResult
            prev_inv = ReleaseInvestigationResult(
                candidate=candidate,
                gaps=assessment.gaps,
                admitted_evidence=assessment.discovered_evidence,
            )

            # Invalidate expired evidence in lifecycle
            for ev_id in expired_evidence_ids:
                self.lifecycle_manager.mark_stale(
                    evidence_id=ev_id,
                    event_id=f"drift-{int(time.time())}",
                    reason="Validity TTL expired via ContinuousDriftMonitor",
                )

            # Reinvestigate affected leaf gaps
            affected_gaps = ["GAP-CI-VALIDATION", "GAP-SECURITY-SAST", "GAP-SECURITY-SCA", "GAP-OPERATIONS-READY"]
            reinv_result = self.investigator.reinvestigate_targeted(
                candidate=candidate,
                previous_result=prev_inv,
                affected_gap_ids=affected_gaps,
                invalidated_evidence_ids=expired_evidence_ids,
            )

            new_decision = self.decision_engine.evaluate_decision(reinv_result)
            new_assessment = ReleaseAssessment(
                candidate=candidate,
                decision=new_decision,
                discovered_evidence=reinv_result.admitted_evidence,
                gaps=reinv_result.gaps,
                contradictions=reinv_result.contradictions,
                telemetry=reinv_result.telemetry,
            )
            self._assessments[candidate.release_id] = new_assessment

            if self.store:
                if hasattr(self.store, "investigations"):
                    self.store.investigations.save_investigation(reinv_result)
                if hasattr(self.store, "decisions"):
                    self.store.decisions.save_decision(new_decision)

            return new_assessment
