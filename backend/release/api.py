"""
Application-Level Release Readiness API (Brick 4.0)

Exposes high-level operations for user workflows, CI/CD webhooks, and UI consumption:
- assess_release(candidate)
- get_assessment(assessment_id)
- get_investigation(release_id)
- get_decision(release_id)
- get_evidence(release_id)
- get_recommendations(release_id)
- propose_action(...) / authorize_action(...) / execute_action(...) / verify_action(...)
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

import httpx

from backend.evidence.models import Evidence
from backend.release.actions import (
    GovernedActionExecutor,
    LiveActionDispatcher,
    SimulatedActionDispatcher,
)
from backend.release.config import OracleReleaseConfig, ProviderFactory, ProviderMode
from backend.release.correlation import CrossSystemCorrelator
from backend.release.decision import ReleaseDecisionEngine
from backend.release.investigation import ReleaseInvestigationResult, ReleaseReadinessInvestigator
from backend.release.models import (
    GovernedActionProposal,
    ReleaseAssessment,
    ReleaseCandidate,
    ReleaseDecision,
    ReleaseRecommendation,
)
from backend.release.providers import BaseReleaseDataProvider, InMemoryReleaseDataProvider


from backend.release.events import (
    DecisionChangeEvent,
    DecisionLineageRecord,
    DecisionLineageTracker,
    DeterministicEntityResolver,
    EnterpriseEvent,
    EnterpriseEventType,
    EventIdempotencyManager,
    EventRouter,
    EvidenceGraph,
    EvidenceLifecycleManager,
    EvidenceLifecycleRecord,
    EvidenceState,
    GraphEdge,
    GraphNode,
    IngestionReceipt,
    InvestigationImpactAnalyzer,
    WebhookSecurityValidator,
)


class ReleaseReadinessAPI:
    """
    Unified application facade for ORACLE Release Readiness Intelligence (Bricks 4.0, 4.1, 4.2 & 4.3).
    """

    def __init__(
        self,
        provider: Optional[BaseReleaseDataProvider] = None,
        investigator: Optional[ReleaseReadinessInvestigator] = None,
        decision_engine: Optional[ReleaseDecisionEngine] = None,
        action_executor: Optional[GovernedActionExecutor] = None,
        config: Optional[OracleReleaseConfig] = None,
        transport: Optional[httpx.BaseTransport] = None,
        event_router: Optional[EventRouter] = None,
        store: Optional[Any] = None,
    ):
        self.config = config or OracleReleaseConfig()
        self.store = store

        if provider is None:
            self.provider = ProviderFactory.create_provider(self.config, transport=transport)
        else:
            self.provider = provider

        self.investigator = investigator or ReleaseReadinessInvestigator(provider=self.provider, store=self.store)
        self.decision_engine = decision_engine or ReleaseDecisionEngine()

        if action_executor is None:
            if self.config.provider_mode == ProviderMode.OFFLINE:
                dispatcher = SimulatedActionDispatcher()
            else:
                dispatcher = LiveActionDispatcher(
                    credential_provider=self.config.credential_provider,
                    github_base_url=self.config.github_base_url,
                    jira_base_url=self.config.jira_base_url,
                    transport=transport,
                )
            action_repo = self.store.actions if self.store and hasattr(self.store, "actions") else None
            self.action_executor = GovernedActionExecutor(
                dispatcher=dispatcher,
                live_actions_enabled=self.config.live_actions_enabled,
                dry_run=self.config.dry_run_actions,
                action_repo=action_repo,
            )
        else:
            self.action_executor = action_executor

        # Event-driven intelligence router (Bricks 4.3 & 4.4)
        self.event_router = event_router or EventRouter(
            investigator=self.investigator,
            decision_engine=self.decision_engine,
            action_executor=self.action_executor,
            store=self.store,
        )

        # In-memory session registries
        self._assessments: Dict[str, ReleaseAssessment] = {}  # assessment_id -> assessment
        self._release_to_assessment: Dict[str, str] = {}      # release_id -> assessment_id
        self._investigations: Dict[str, ReleaseInvestigationResult] = {}  # release_id -> result

    def assess_release(self, candidate: ReleaseCandidate) -> ReleaseAssessment:
        """
        End-to-end execution of a release assessment:
        Candidate -> Correlation -> Parallel Investigation -> DAG Cascade -> Decision -> Action Proposals.
        """
        # 1. Investigate
        inv_result = self.investigator.investigate(candidate)
        self._investigations[candidate.release_id] = inv_result

        # 2. Derive Decision
        decision = self.decision_engine.evaluate_decision(inv_result)

        # 3. Register Governed Actions
        for action in decision.governed_actions:
            self.action_executor.register_proposal(action)

        # 4. Assemble Top-Level Assessment
        assessment = ReleaseAssessment(
            candidate=candidate,
            decision=decision,
            discovered_evidence=inv_result.admitted_evidence,
            gaps=inv_result.gaps,
            contradictions=inv_result.contradictions,
            telemetry=inv_result.telemetry,
        )

        self._assessments[assessment.assessment_id] = assessment
        self._release_to_assessment[candidate.release_id] = assessment.assessment_id

        # 5. Register with Event Router for continuous event awareness and evidence graph tracking
        self.event_router.register_candidate(candidate, initial_assessment=assessment)

        return assessment

    def get_assessment(self, assessment_id: str) -> Optional[ReleaseAssessment]:
        """Retrieve stored assessment by assessment_id."""
        return self._assessments.get(assessment_id)

    def get_assessment_by_release(self, release_id: str) -> Optional[ReleaseAssessment]:
        """Retrieve stored assessment by release_id, reflecting any event-driven targeted updates."""
        router_assessment = self.event_router.get_assessment(release_id)
        if router_assessment:
            return router_assessment
        aid = self._release_to_assessment.get(release_id)
        return self._assessments.get(aid) if aid else None

    def get_investigation(self, release_id: str) -> Optional[ReleaseInvestigationResult]:
        """Retrieve underlying investigation details."""
        return self._investigations.get(release_id)

    def get_decision(self, release_id: str) -> Optional[ReleaseDecision]:
        """Retrieve authoritative decision for release."""
        assessment = self.get_assessment_by_release(release_id)
        return assessment.decision if assessment else None

    def get_evidence(self, release_id: str) -> List[Evidence]:
        """Retrieve admitted evidence for release."""
        assessment = self.get_assessment_by_release(release_id)
        return assessment.discovered_evidence if assessment else []

    def get_recommendations(self, release_id: str) -> List[ReleaseRecommendation]:
        """Retrieve evidence-backed recommendations for release."""
        decision = self.get_decision(release_id)
        return decision.recommendations if decision else []

    # -------------------------------------------------------------------------
    # GOVERNED ACTIONS DELEGATION
    # -------------------------------------------------------------------------

    def propose_action(self, proposal: GovernedActionProposal) -> GovernedActionProposal:
        return self.action_executor.register_proposal(proposal)

    def authorize_action(self, action_id: str, authorizer: str, human_approved: bool = True) -> GovernedActionProposal:
        return self.action_executor.authorize_action(action_id, authorized_by=authorizer, human_approved=human_approved)

    def execute_action(self, action_id: str) -> Dict[str, Any]:
        return self.action_executor.execute_action(action_id)

    def verify_action(self, action_id: str) -> bool:
        return self.action_executor.verify_action(action_id)

    # -------------------------------------------------------------------------
    # BRICK 4.3: EVENT-DRIVEN INTELLIGENCE & EVIDENCE GRAPH
    # -------------------------------------------------------------------------

    def ingest_webhook(
        self,
        source: str,
        event_name: str,
        payload: Dict[str, Any],
        raw_body: Optional[bytes] = None,
        headers: Optional[Dict[str, str]] = None,
        secret: Optional[str] = None,
    ) -> IngestionReceipt:
        """Ingest external webhook payload through security, normalization, idempotency, and targeted re-investigation."""
        return self.event_router.ingest_webhook(
            source=source,
            event_name=event_name,
            payload=payload,
            raw_body=raw_body,
            headers=headers,
            secret=secret,
        )

    def ingest_event(self, event: EnterpriseEvent) -> IngestionReceipt:
        """Direct ingestion of canonical EnterpriseEvent."""
        return self.event_router.process_event(event)

    def get_event(self, event_id: str) -> Optional[EnterpriseEvent]:
        """Retrieve a processed enterprise event by ID."""
        for evt in self.event_router.get_event_history():
            if evt.event_id == event_id:
                return evt
        return None

    def get_event_history(self, release_id: Optional[str] = None) -> List[EnterpriseEvent]:
        """Retrieve chronological history of ingested enterprise events."""
        return self.event_router.get_event_history(release_id=release_id)

    def get_entity(self, entity_id: str) -> Optional[GraphNode]:
        """Retrieve node from the enterprise evidence graph."""
        return self.event_router.evidence_graph.get_node(entity_id)

    def get_entity_relationships(
        self, entity_id: str, direction: str = "out", active_only: bool = True
    ) -> List[GraphEdge]:
        """Query inbound, outbound, or all relationships for an entity in the evidence graph."""
        return self.event_router.evidence_graph.get_edges(entity_id=entity_id, direction=direction, active_only=active_only)

    def get_investigation_lineage(self, release_id: str) -> List[DecisionLineageRecord]:
        """Retrieve complete decision lineage for a release."""
        return self.event_router.lineage_tracker.get_lineage(release_id)

    def get_decision_history(self, release_id: str) -> List[ReleaseDecision]:
        """Retrieve chronological list of decisions evaluated for a release."""
        return [rec.decision for rec in self.event_router.lineage_tracker.get_lineage(release_id)]

    def get_decision_change_reason(self, release_id: str) -> Optional[str]:
        """Explain in deterministic natural language why ORACLE's decision shifted."""
        return self.event_router.lineage_tracker.explain_latest_change(release_id)

    def get_evidence_lineage(self, evidence_id: str) -> Optional[EvidenceLifecycleRecord]:
        """Retrieve lifecycle states (VALID, STALE, etc.) and transition history for an evidence unit."""
        return self.event_router.lifecycle_manager.get_record(evidence_id)
