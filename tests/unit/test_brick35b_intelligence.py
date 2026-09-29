"""
Brick 3.5B — Investigation Intelligence & Semantic Retrieval Test Suite

Comprehensive test suite verifying:
- Semantic Query Deduplication (positive & negative controls, intent compatibility)
- Entity Coreference Resolution (high-confidence resolution, ambiguous safety)
- Diamond DAG Correctness, Validation (cycle, self-dependency), and Dynamic Replanning
- 5 Realistic End-to-End Investigations (Production Deployment, Vendor Onboarding,
  Infrastructure Migration, Security Incident, Product Launch)
- Performance & Latency Benchmarks
"""

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional, Set, Tuple

import pytest

from backend.evidence.models import Evidence
from backend.investigation.controller import (
    InvestigationBudget,
    InvestigationController,
    InvestigationSession,
    InvestigationState,
)
from backend.investigation.coreference import ControlledCoreferenceResolver
from backend.investigation.dag import DependencyGraph
from backend.investigation.evaluator import EntityScopedEvaluator
from backend.investigation.models import (
    ActionStatus,
    EvidenceEdge,
    GapStatus,
    GapType,
    InformationGap,
    InvestigationAction,
)
from backend.investigation.semantic_dedup import (
    InvestigativeOperation,
    LocalSemanticEmbeddingProvider,
    SemanticQueryDeduplicator,
)
from backend.retrieval.provider import EvidenceProvider


# -----------------------------------------------------------------------------
# Test Fixtures & Helpers
# -----------------------------------------------------------------------------

from tests.unit.test_brick35a_hardening import (
    MockMemoryRetriever as MockRetriever,
    make_test_evidence as make_evidence,
)


# =============================================================================
# PART 1: SEMANTIC DEDUPLICATION (Tests 1-10)
# =============================================================================

class TestSemanticDeduplication:

    @pytest.fixture(autouse=True)
    def setup(self):
        self.dedup = SemanticQueryDeduplicator(semantic_threshold=0.75, lexical_threshold=0.70)

    def test_01_exact_duplicate(self):
        """1. Exact string match is flagged immediately with similarity 1.0."""
        q = "verify change request CR-88 status"
        res = self.dedup.is_semantically_duplicate(q, q)
        assert res.is_duplicate is True
        assert res.similarity_score == 1.0
        assert res.provenance["method"] == "EXACT_LEXICAL"

    def test_02_keyword_shuffled_duplicate(self):
        """2. Keyword-shuffled duplicate is caught by lexical Jaccard gate."""
        q1 = "payment gateway mutual tls requirements"
        q2 = "requirements mutual tls payment gateway"
        res = self.dedup.is_semantically_duplicate(q2, q1)
        assert res.is_duplicate is True
        assert res.provenance["method"] == "LEXICAL_JACCARD"

    def test_03_strong_paraphrase(self):
        """3. Strong paraphrase with concept synonyms is detected via semantic embedding."""
        q1 = "payment gateway mutual tls requirements"
        q2 = "checkout service cryptographic handshake protocol"
        res = self.dedup.is_semantically_duplicate(q2, q1)
        assert res.is_duplicate is True
        assert res.similarity_score >= 0.75
        assert res.provenance["method"] == "SEMANTIC_EMBEDDING"

    def test_04_different_vocabulary_same_intent(self):
        """4. Different surface vocabulary expressing identical CAB approval intent."""
        q1 = "Change Advisory Board meeting 88 approval status"
        q2 = "Has CAB authorized deployment #88?"
        res = self.dedup.is_semantically_duplicate(q2, q1)
        assert res.is_duplicate is True
        assert res.similarity_score >= 0.75

    def test_05_same_entity_different_predicate(self):
        """5. Same entity with distinct operational predicates must NOT be deduplicated."""
        q1 = "Was CR-88 approved?"
        q2 = "Was CR-88 executed successfully?"
        res = self.dedup.is_semantically_duplicate(q2, q1)
        assert res.is_duplicate is False
        assert res.contextual_compatibility is False
        assert "Distinct investigative operations" in (res.rejection_reason or "")

    def test_06_same_predicate_different_entity(self):
        """6. Same predicate on different target entities must NOT be deduplicated."""
        q1 = "Was Redis cluster rollback completed?"
        q2 = "Was Kafka broker rollback completed?"
        res = self.dedup.is_semantically_duplicate(q2, q1)
        assert res.is_duplicate is False
        assert res.contextual_compatibility is False
        assert "Different target entities" in (res.rejection_reason or "")

    def test_07_same_topic_different_intent(self):
        """7. Same topic (migration) but opposing intents (approval vs rollback)."""
        q1 = "Was Phoenix migration approved?"
        q2 = "Was Phoenix migration rolled back?"
        res = self.dedup.is_semantically_duplicate(q2, q1)
        assert res.is_duplicate is False
        assert res.contextual_compatibility is False

    def test_08_semantically_related_non_duplicate(self):
        """8. Related infrastructure components are not falsely collapsed."""
        q1 = "Postgres database replication lag metrics"
        q2 = "Postgres database automated backup status"
        res = self.dedup.is_semantically_duplicate(q2, q1)
        assert res.is_duplicate is False

    def test_09_different_operational_identifiers(self):
        """9. Queries identical except for ticket number must NOT be deduplicated."""
        q1 = "Was change request CR-901 approved?"
        q2 = "Was change request CR-902 approved?"
        res = self.dedup.is_semantically_duplicate(q2, q1)
        assert res.is_duplicate is False
        assert "Different operational identifiers" in (res.rejection_reason or "")

    def test_10_different_temporal_scope(self):
        """10. Preserves queries targeting distinct operational windows."""
        q1 = "service deployment status tonight"
        q2 = "service deployment status weekend"
        res = self.dedup.is_semantically_duplicate(q2, q1)
        # They should not be conflated as identical
        assert res.similarity_score < 0.95


# =============================================================================
# PART 2: COREFERENCE RESOLUTION (Tests 11-18)
# =============================================================================

class TestCoreferenceResolution:

    @pytest.fixture(autouse=True)
    def setup(self):
        self.resolver = ControlledCoreferenceResolver(confidence_threshold=0.80)
        self.evaluator = EntityScopedEvaluator(coref_resolver=self.resolver)

    def test_11_simple_it_reference(self):
        """11. 'it' resolving to single unambiguous project antecedent in prior clause."""
        text = "Project Phoenix was scheduled for Friday. It was subsequently cancelled due to Sev-1."
        resolved = self.resolver.resolve_chunk(text)
        assert len(resolved) == 2
        assert "PROJECT PHOENIX" in resolved[1].effective_entities
        assert resolved[1].inferred_bindings[0].confidence >= 0.80

    def test_12_this_project_reference(self):
        """12. 'this project' resolving to named project."""
        text = "Project Phoenix passed security scan. This project is cleared for release."
        resolved = self.resolver.resolve_chunk(text)
        assert "PROJECT PHOENIX" in resolved[1].effective_entities
        assert resolved[1].inferred_bindings[0].reference_expression.lower() == "this project"

    def test_13_multi_sentence_ticket_reference(self):
        """13. 'this change' resolving across sentences to CR-904."""
        text = "CR-904 was reviewed by the architecture team on Tuesday. All questions were resolved. This change is approved."
        resolved = self.resolver.resolve_chunk(text)
        assert len(resolved) == 3
        assert "CR-904" in resolved[2].effective_entities

    def test_14_ambiguous_pronoun_two_antecedents(self):
        """14. Ambiguous pronoun with 2 competing antecedents in same sentence is NOT bound."""
        text = "Project Phoenix depends on Payment Gateway. It was deployed yesterday."
        resolved = self.resolver.resolve_chunk(text)
        assert resolved[1].inferred_bindings[0].is_ambiguous is True
        # False attribution must be prevented
        assert len(resolved[1].effective_entities) == 0

    def test_15_incident_category_disambiguation(self):
        """15. Category-anchored reference 'the incident' binds only to INC ticket, not CR ticket."""
        text = "CR-904 was scheduled while INC-402 was active. The incident was mitigated at 04:00 UTC."
        resolved = self.resolver.resolve_chunk(text)
        assert "INC-402" in resolved[1].effective_entities
        assert "CR-904" not in resolved[1].effective_entities

    def test_16_cross_entity_pronoun_ambiguity(self):
        """16. Cross-entity pronoun ambiguity leaves evidence unassigned."""
        text = "Redis Cluster and Kafka Broker experienced high load. They were restarted."
        resolved = self.resolver.resolve_chunk(text)
        assert resolved[1].inferred_bindings[0].is_ambiguous is True
        assert len(resolved[1].effective_entities) == 0

    def test_17_high_confidence_evaluator_satisfaction(self):
        """17. Evaluator satisfies gap when second sentence uses coreference 'it'."""
        gap = InformationGap(
            gap_id="GAP-PHX-STATUS",
            target_entity="Project Phoenix",
            description="Project Phoenix cancellation status",
            required_information="cancelled due to incident",
            status=GapStatus.OPEN,
        )
        ev = make_evidence(
            "EV-COREF",
            "Project Phoenix was scheduled for Friday. It was subsequently cancelled due to Sev-1.",
        )
        res = self.evaluator.evaluate_chunk(gap, ev)
        # Should detect conflict/cancellation for Project Phoenix
        assert res.chunk_conflicts is True

    def test_18_low_confidence_unresolved_safety(self):
        """18. Ambiguous coreference prevents incorrect satisfaction of gap."""
        gap = InformationGap(
            gap_id="GAP-PAYMENT",
            target_entity="Payment Gateway",
            description="Payment Gateway deployment status",
            required_information="deployed yesterday",
            status=GapStatus.OPEN,
        )
        # Ambiguous sentence: could refer to Phoenix or Payment Gateway
        ev = make_evidence("EV-AMBIG", "Project Phoenix depends on Payment Gateway. It was deployed yesterday.")
        res = self.evaluator.evaluate_chunk(gap, ev)
        # Because 'it' is ambiguous, it must NOT satisfy Payment Gateway
        assert res.chunk_satisfies is False


# =============================================================================
# PART 3: DIAMOND DAG & GRAPH VALIDATION (Tests 19-28)
# =============================================================================

class TestDiamondDAGAndValidation:

    def test_19_simple_chain_propagation(self):
        """19. Linear chain A -> B -> C invalidation propagation."""
        dag = DependencyGraph()
        gaps = {
            "A": InformationGap(gap_id="A", description="A", status=GapStatus.RESOLVED),
            "B": InformationGap(gap_id="B", description="B", status=GapStatus.RESOLVED),
            "C": InformationGap(gap_id="C", description="C", status=GapStatus.RESOLVED),
        }
        ids = set(gaps.keys())
        dag.add_dependency("B", "A", ids, gaps)
        dag.add_dependency("C", "B", ids, gaps)

        # Invalidate A -> cascades to B and C
        gaps["A"].status = GapStatus.REOPENED
        dag.propagate_invalidation("A", gaps)
        assert gaps["B"].status == GapStatus.DEPENDENCY_UNSATISFIED
        assert gaps["C"].status == GapStatus.DEPENDENCY_UNSATISFIED

    def test_20_diamond_dag_partial_restoration(self):
        """20. Diamond DAG: Restoring B alone leaves D in DEPENDENCY_UNSATISFIED until C resolves."""
        dag = DependencyGraph()
        gaps = {
            "A": InformationGap(gap_id="A", description="A", status=GapStatus.OPEN),
            "B": InformationGap(gap_id="B", description="B", status=GapStatus.OPEN),
            "C": InformationGap(gap_id="C", description="C", status=GapStatus.OPEN),
            "D": InformationGap(gap_id="D", description="D", status=GapStatus.OPEN),
        }
        ids = set(gaps.keys())
        dag.add_dependency("B", "A", ids, gaps)
        dag.add_dependency("C", "A", ids, gaps)
        dag.add_dependency("D", "B", ids, gaps)
        dag.add_dependency("D", "C", ids, gaps)

        # A resolves -> B and C become eligible
        gaps["A"].status = GapStatus.RESOLVED
        dag.propagate_restoration("A", gaps)
        assert gaps["B"].status == GapStatus.OPEN
        assert gaps["C"].status == GapStatus.OPEN
        assert gaps["D"].status == GapStatus.DEPENDENCY_UNSATISFIED

        # B resolves, but C is unresolved -> D MUST REMAIN DEPENDENCY_UNSATISFIED
        gaps["B"].status = GapStatus.RESOLVED
        dag.propagate_restoration("B", gaps)
        assert gaps["D"].status == GapStatus.DEPENDENCY_UNSATISFIED
        assert gaps["D"].unsatisfied_prerequisites == ["C"]

    def test_21_diamond_dag_full_restoration(self):
        """21. Diamond DAG: When both B and C resolve, D transitions to OPEN."""
        dag = DependencyGraph()
        gaps = {
            "A": InformationGap(gap_id="A", description="A", status=GapStatus.RESOLVED),
            "B": InformationGap(gap_id="B", description="B", status=GapStatus.RESOLVED),
            "C": InformationGap(gap_id="C", description="C", status=GapStatus.OPEN),
            "D": InformationGap(gap_id="D", description="D", status=GapStatus.DEPENDENCY_UNSATISFIED),
        }
        ids = set(gaps.keys())
        dag.add_dependency("B", "A", ids, gaps)
        dag.add_dependency("C", "A", ids, gaps)
        dag.add_dependency("D", "B", ids, gaps)
        dag.add_dependency("D", "C", ids, gaps)

        # C resolves -> D now has all prerequisites satisfied
        gaps["C"].status = GapStatus.RESOLVED
        dag.propagate_restoration("C", gaps)
        assert gaps["D"].status == GapStatus.OPEN
        assert gaps["D"].unsatisfied_prerequisites == []

    def test_22_multiple_parent_dependency(self):
        """22. Gap depending on 3 parallel parents."""
        dag = DependencyGraph()
        gaps = {
            "P1": InformationGap(gap_id="P1", description="P1", status=GapStatus.RESOLVED),
            "P2": InformationGap(gap_id="P2", description="P2", status=GapStatus.RESOLVED),
            "P3": InformationGap(gap_id="P3", description="P3", status=GapStatus.OPEN),
            "CHILD": InformationGap(gap_id="CHILD", description="CHILD", status=GapStatus.OPEN),
        }
        ids = set(gaps.keys())
        dag.add_dependency("CHILD", "P1", ids, gaps)
        dag.add_dependency("CHILD", "P2", ids, gaps)
        dag.add_dependency("CHILD", "P3", ids, gaps)

        assert gaps["CHILD"].status == GapStatus.DEPENDENCY_UNSATISFIED
        assert "P3" in gaps["CHILD"].unsatisfied_prerequisites

        # Resolve P3
        gaps["P3"].status = GapStatus.RESOLVED
        dag.propagate_restoration("P3", gaps)
        assert gaps["CHILD"].status == GapStatus.OPEN

    def test_23_cycle_rejection_direct(self):
        """23. Direct cycle A -> B -> A is deterministically rejected."""
        dag = DependencyGraph()
        gaps = {
            "A": InformationGap(gap_id="A", description="A"),
            "B": InformationGap(gap_id="B", description="B"),
        }
        ids = set(gaps.keys())
        res1 = dag.add_dependency("B", "A", ids, gaps)
        assert res1.is_valid is True

        res2 = dag.add_dependency("A", "B", ids, gaps)
        assert res2.is_valid is False
        assert res2.error_type == "CYCLE_DETECTED"
        assert res2.cycle_path is not None

    def test_24_cycle_rejection_transitive(self):
        """24. Long cycle A -> B -> C -> D -> A is deterministically rejected."""
        dag = DependencyGraph()
        gaps = {k: InformationGap(gap_id=k, description=k) for k in ["A", "B", "C", "D"]}
        ids = set(gaps.keys())
        dag.add_dependency("B", "A", ids, gaps)
        dag.add_dependency("C", "B", ids, gaps)
        dag.add_dependency("D", "C", ids, gaps)

        # Attempt to close the loop
        res = dag.add_dependency("A", "D", ids, gaps)
        assert res.is_valid is False
        assert res.error_type == "CYCLE_DETECTED"

    def test_25_self_dependency_rejection(self):
        """25. Self dependency A -> A is rejected."""
        dag = DependencyGraph()
        gaps = {"A": InformationGap(gap_id="A", description="A")}
        ids = set(gaps.keys())
        res = dag.add_dependency("A", "A", ids, gaps)
        assert res.is_valid is False
        assert res.error_type == "SELF_DEPENDENCY"

    def test_26_nonexistent_dependency_rejection(self):
        """26. Dependency referencing a nonexistent gap is rejected."""
        dag = DependencyGraph()
        gaps = {"A": InformationGap(gap_id="A", description="A")}
        ids = set(gaps.keys())
        res = dag.add_dependency("A", "NONEXISTENT", ids, gaps)
        assert res.is_valid is False
        assert res.error_type == "NONEXISTENT_GAP"

    def test_27_repeated_invalidation_and_restoration(self):
        """27. Repeated cycles of invalidation and restoration behave deterministically."""
        dag = DependencyGraph()
        gaps = {
            "A": InformationGap(gap_id="A", description="A", status=GapStatus.OPEN),
            "B": InformationGap(gap_id="B", description="B", status=GapStatus.OPEN),
        }
        ids = set(gaps.keys())
        dag.add_dependency("B", "A", ids, gaps)

        # Cycle 1: A resolves -> B open
        gaps["A"].status = GapStatus.RESOLVED
        dag.propagate_restoration("A", gaps)
        assert gaps["B"].status == GapStatus.OPEN

        # Cycle 2: A invalidated -> B unsatisfied
        gaps["A"].status = GapStatus.REOPENED
        dag.propagate_invalidation("A", gaps)
        assert gaps["B"].status == GapStatus.DEPENDENCY_UNSATISFIED

        # Cycle 3: A resolves again -> B open again
        gaps["A"].status = GapStatus.RESOLVED
        dag.propagate_restoration("A", gaps)
        assert gaps["B"].status == GapStatus.OPEN

    def test_28_controller_authority_enforces_dag_rejection(self):
        """28. Controller blocks actions targeting gaps in DEPENDENCY_UNSATISFIED state."""
        retriever = MockRetriever()
        ctrl = InvestigationController(retriever=retriever)
        session = InvestigationSession(session_id="s_dag_auth", objective="test")

        gap_a = InformationGap(gap_id="GAP-A", description="Prereq gap A", status=GapStatus.OPEN)
        gap_b = InformationGap(gap_id="GAP-B", description="Dependent gap B", status=GapStatus.OPEN)
        session.gaps["GAP-A"] = gap_a
        session.gaps["GAP-B"] = gap_b

        ctrl.register_gap_dependency(session, "GAP-B", "GAP-A")
        assert gap_b.status == GapStatus.DEPENDENCY_UNSATISFIED

        # LLM proposes action against GAP-B before GAP-A is resolved
        act = InvestigationAction(action_id="ACT-1", gap_id="GAP-B", query="Check B details", reason="testing")
        valid, reason = ctrl.validate_action(act, session)
        assert valid is False
        assert "unsatisfied prerequisites" in (reason or "").lower()


# =============================================================================
# PART 4: 5 REALISTIC END-TO-END INVESTIGATIONS (Tests 29-33)
# =============================================================================

class TestRealisticInvestigations:

    def test_29_production_deployment_decision(self):
        """
        Scenario 1: Production Deployment Decision
        Question: 'Can Payment Gateway v4.8 safely deploy tonight?'
        """
        retriever = MockRetriever()
        retriever.add_canned_response("can payment gateway", [
            make_evidence("EV-CR-48", "CAB DECISION: Change request CR-48 for Payment Gateway v4.8 is APPROVED for deployment tonight.", "DOC-CAB-48"),
            make_evidence("EV-SEC-48", "Security Review: Payment Gateway v4.8 mTLS cryptographic handshake validation PASSED.", "DOC-SEC-48"),
        ])
        retriever.add_canned_response("payment gateway rollback plan", [
            make_evidence("EV-RB-48", "Operational Plan: Payment Gateway v4.8 rollback plan verified and backup confirmed.", "DOC-OPS-48"),
        ])

        budget = InvestigationBudget(max_hops=4, max_llm_calls=5, max_queries=15)
        ctrl = InvestigationController(retriever=retriever, budget=budget)

        def reasoning_agent(state: InvestigationState):
            accum = set(state.accumulated_evidence.keys())
            if "EV-CR-48" not in accum:
                return False, "Check CAB approval", [
                    InformationGap(gap_id="GAP-CAB", gap_type=GapType.AUTHORITY_RESOLUTION, is_blocking=True, target_entity="Payment Gateway", description="CAB approval", targeted_query="Payment Gateway CR-48 approval")
                ], []
            if "EV-RB-48" not in accum:
                return False, "Check rollback readiness", [
                    InformationGap(gap_id="GAP-RB", gap_type=GapType.PREREQUISITE, is_blocking=True, target_entity="Payment Gateway", description="Rollback plan", targeted_query="Payment Gateway rollback plan")
                ], []
            return True, "All deployment gates satisfied", [], []

        package = ctrl.run_investigation("Can Payment Gateway v4.8 safely deploy tonight?", reasoning_agent_fn=reasoning_agent)
        assert package.controller_verified is True
        assert package.termination_reason == "SUFFICIENT"

    def test_30_vendor_onboarding(self):
        """
        Scenario 2: Vendor Onboarding
        Question: 'Can we safely onboard Vendor AcmeCloud?'
        """
        retriever = MockRetriever()
        retriever.add_canned_response("can we safely onboard", [
            make_evidence("EV-INIT-VEND", "Vendor Assessment: Evaluating AcmeCloud vendor security and legal profile.", "DOC-INIT"),
        ])
        retriever.add_canned_response("acmecloud vendor onboarding contracts", [
            make_evidence("EV-CONTRACT", "Vendor Onboarding: AcmeCloud MSA and SLA contracts APPROVED by legal.", "DOC-LEGAL"),
            make_evidence("EV-SOC2", "Compliance Status: AcmeCloud SOC-2 Type II audit report VALID and compliance confirmed.", "DOC-COMPL"),
        ])
        retriever.add_canned_response("acmecloud security review", [
            make_evidence("EV-VEND-SEC", "InfoSec Review: AcmeCloud network penetration test PASSED with zero high security vulnerabilities.", "DOC-SEC"),
        ])

        budget = InvestigationBudget(max_hops=4, max_llm_calls=5, max_queries=15)
        ctrl = InvestigationController(retriever=retriever, budget=budget)

        def reasoning_agent(state: InvestigationState):
            accum = set(state.accumulated_evidence.keys())
            if "EV-CONTRACT" not in accum:
                return False, "Check contracts and compliance", [
                    InformationGap(gap_id="GAP-CONTRACT", gap_type=GapType.PREREQUISITE, is_blocking=True, target_entity="AcmeCloud", description="Legal approval", required_information="contracts APPROVED by legal", targeted_query="AcmeCloud vendor onboarding contracts")
                ], []
            if "EV-VEND-SEC" not in accum:
                return False, "Check InfoSec validation", [
                    InformationGap(gap_id="GAP-SEC", gap_type=GapType.PREREQUISITE, is_blocking=True, target_entity="AcmeCloud", description="Security validation", required_information="penetration test PASSED", targeted_query="AcmeCloud security review")
                ], []
            return True, "Vendor onboarding gates fully satisfied", [], []

        package = ctrl.run_investigation("Can we safely onboard Vendor AcmeCloud?", reasoning_agent_fn=reasoning_agent)
        assert package.controller_verified is True
        assert package.termination_reason == "SUFFICIENT"

    def test_31_infrastructure_migration(self):
        """
        Scenario 3: Infrastructure Migration with Reopened Gap
        Question: 'Can database cluster Postgres-01 be migrated this weekend?'
        """
        retriever = MockRetriever()
        retriever.add_canned_response("postgres-01", [
            make_evidence("EV-PG-MIG", "Database Migration RFC-202: Postgres-01 cluster migration is APPROVED for Saturday 02:00 UTC.", "DOC-RFC-202"),
        ])
        retriever.add_canned_response("backup", [
            make_evidence("EV-PG-BAK", "Backup Verification: Postgres-01 automated snapshot FAILED due to disk space shortage.", "DOC-BAK-LOG"),
        ])

        budget = InvestigationBudget(max_hops=4, max_llm_calls=5, max_queries=15)
        ctrl = InvestigationController(retriever=retriever, budget=budget)

        def reasoning_agent(state: InvestigationState):
            accum = set(state.accumulated_evidence.keys())
            if "EV-PG-MIG" not in accum:
                return False, "Check RFC approval", [
                    InformationGap(gap_id="GAP-RFC", gap_type=GapType.AUTHORITY_RESOLUTION, is_blocking=True, target_entity="Postgres-01", description="RFC approval", targeted_query="Postgres-01 RFC-202 approval")
                ], []
            if "EV-PG-BAK" not in accum:
                return False, "Verify backup", [
                    InformationGap(gap_id="GAP-BAK", gap_type=GapType.PREREQUISITE, is_blocking=True, target_entity="Postgres-01", description="Backup verification", targeted_query="Postgres-01 backup verification")
                ], []
            return True, "Attempting sufficiency", [], []

        package = ctrl.run_investigation("Can database cluster Postgres-01 be migrated this weekend?", reasoning_agent_fn=reasoning_agent)
        # Because backup FAILED, the blocking gap cannot be satisfied -> controller terminates without verification
        assert package.controller_verified is False

    def test_32_security_incident_remediation(self):
        """
        Scenario 4: Security Incident Remediation & Closure
        Question: 'Has incident INC-402 been sufficiently remediated to close?'
        """
        retriever = MockRetriever()
        retriever.add_canned_response("has incident inc-402", [
            make_evidence("EV-INIT-INC", "Incident Overview: INC-402 priority incident opened for security investigation.", "DOC-INIT-INC"),
        ])
        retriever.add_canned_response("inc-402 root cause", [
            make_evidence("EV-INC-RCA", "INC-402 Postmortem: Root cause identified as unauthenticated Redis port exposure. Vulnerability PATCHED.", "DOC-INC-402"),
        ])
        retriever.add_canned_response("inc-402 monitoring", [
            make_evidence("EV-INC-MON", "INC-402 Verification: Network monitoring ENABLED and all security audit checks PASSED. DECISION: INC-402 is RESOLVED and CLOSED.", "DOC-MON-402"),
        ])

        budget = InvestigationBudget(max_hops=4, max_llm_calls=5, max_queries=15)
        ctrl = InvestigationController(retriever=retriever, budget=budget)

        def reasoning_agent(state: InvestigationState):
            accum = set(state.accumulated_evidence.keys())
            if "EV-INC-RCA" not in accum:
                return False, "Check root cause patch", [
                    InformationGap(gap_id="GAP-RCA", gap_type=GapType.PREREQUISITE, is_blocking=True, target_entity="INC-402", description="Root cause patch", required_information="vulnerability PATCHED", targeted_query="INC-402 root cause")
                ], []
            if "EV-INC-MON" not in accum:
                return False, "Check monitoring validation", [
                    InformationGap(gap_id="GAP-MON", gap_type=GapType.PREREQUISITE, is_blocking=True, target_entity="INC-402", description="Monitoring enabled", required_information="INC-402 is RESOLVED and CLOSED", targeted_query="INC-402 monitoring")
                ], []
            return True, "Incident remediation complete", [], []

        package = ctrl.run_investigation("Has incident INC-402 been sufficiently remediated to close?", reasoning_agent_fn=reasoning_agent)
        assert package.controller_verified is True
        assert package.termination_reason == "SUFFICIENT"

    def test_33_product_launch_full_cycle(self):
        """
        Scenario 5: Product Launch Verification (Phoenix)
        Full lifecycle with coreference, semantic query deduplication, and DAG validation.
        """
        retriever = MockRetriever()
        retriever.add_canned_response("is project phoenix ready", [
            make_evidence("EV-INIT-PHX", "Project Phoenix Launch Gate: Multi-stage release verification starting.", "DOC-INIT-PHX"),
        ])
        retriever.add_canned_response("project phoenix cab approval", [
            make_evidence("EV-PHX-AUTH", "Security CAB DECISION: Project Phoenix release is APPROVED for external launch.", "DOC-PHX-CAB"),
        ])
        retriever.add_canned_response("phoenix automated smoke test suite", [
            make_evidence("EV-PHX-VAL", "Automated Smoke Tests: Project Phoenix end-to-end integration suite PASSED with 100% success rate.", "DOC-PHX-TEST"),
        ])

        budget = InvestigationBudget(max_hops=4, max_llm_calls=5, max_queries=15)
        ctrl = InvestigationController(retriever=retriever, budget=budget)

        call_count = 0

        def reasoning_agent(state: InvestigationState):
            nonlocal call_count
            call_count += 1
            accum = set(state.accumulated_evidence.keys())
            if "EV-PHX-AUTH" not in accum:
                return False, "Querying CAB approval", [
                    InformationGap(gap_id="GAP-AUTH", gap_type=GapType.AUTHORITY_RESOLUTION, is_blocking=True, target_entity="Project Phoenix", description="CAB approval", targeted_query="Project Phoenix CAB approval")
                ], []
            if call_count == 2:
                # LLM tries to propose a semantic duplicate query!
                # "Has CAB authorized Project Phoenix?" is duplicate of "Project Phoenix CAB approval"
                return False, "Attempting paraphrased query", [
                    InformationGap(gap_id="GAP-DUP", gap_type=GapType.PREREQUISITE, is_blocking=False, target_entity="Project Phoenix", description="Duplicate check", targeted_query="Has CAB authorized Project Phoenix?")
                ], []
            if "EV-PHX-VAL" not in accum:
                return False, "Querying smoke test validation", [
                    InformationGap(gap_id="GAP-SMOKE", gap_type=GapType.PREREQUISITE, is_blocking=True, target_entity="Project Phoenix", description="Smoke test suite", targeted_query="Phoenix automated smoke test suite")
                ], []
            return True, "Launch prerequisites verified", [], []

        package = ctrl.run_investigation("Is Project Phoenix ready for external launch?", reasoning_agent_fn=reasoning_agent)
        assert package.controller_verified is True
        # Verify that the semantic duplicate was caught in trace
        dedup_events = [e for e in package.investigation_trace if e.event_type == "SEMANTIC_QUERY_DEDUPLICATION_REJECTION"]
        assert len(dedup_events) >= 1, "Expected semantic query deduplication rejection in trace"


# =============================================================================
# PART 5: PERFORMANCE BENCHMARKS (Test 34)
# =============================================================================

class TestPerformanceBenchmarks:

    def test_34_performance_and_latency_benchmarks(self):
        """
        Verify sub-millisecond lexical dedup, embedding cache hit rate,
        and rapid DAG cycle detection latency.
        """
        dedup = SemanticQueryDeduplicator()

        # 1. Lexical fast gate latency (< 0.1 ms)
        t0 = time.perf_counter()
        for _ in range(100):
            dedup.is_semantically_duplicate("test query A", "test query A")
        lexical_lat_ms = ((time.perf_counter() - t0) / 100) * 1000
        assert lexical_lat_ms < 0.5, f"Lexical dedup too slow: {lexical_lat_ms:.3f} ms"

        # 2. Embedding generation & caching latency (< 0.5 ms cached)
        embedder = LocalSemanticEmbeddingProvider()
        # Warmup
        embedder.embed("sample investigation query for caching")
        t0 = time.perf_counter()
        for _ in range(100):
            embedder.embed("sample investigation query for caching")
        cached_lat_ms = ((time.perf_counter() - t0) / 100) * 1000
        assert cached_lat_ms < 0.1, f"Cached embedding too slow: {cached_lat_ms:.3f} ms"

        # 3. Coreference resolution latency (< 1.0 ms per chunk)
        resolver = ControlledCoreferenceResolver()
        sample_chunk = "Project Phoenix was scheduled for Friday. It was subsequently cancelled due to Sev-1."
        t0 = time.perf_counter()
        for _ in range(50):
            resolver.resolve_chunk(sample_chunk)
        coref_lat_ms = ((time.perf_counter() - t0) / 50) * 1000
        assert coref_lat_ms < 1.0, f"Coreference resolution too slow: {coref_lat_ms:.3f} ms"

        # 4. DAG Cycle detection latency on 20-node graph (< 0.5 ms)
        dag = DependencyGraph()
        nodes = [f"G{i}" for i in range(20)]
        ids = set(nodes)
        for i in range(len(nodes) - 1):
            dag.add_dependency(nodes[i+1], nodes[i], ids)
        t0 = time.perf_counter()
        for _ in range(50):
            dag.validate_dependency(nodes[0], nodes[-1], ids)
        dag_lat_ms = ((time.perf_counter() - t0) / 50) * 1000
        assert dag_lat_ms < 0.5, f"DAG cycle check too slow: {dag_lat_ms:.3f} ms"
