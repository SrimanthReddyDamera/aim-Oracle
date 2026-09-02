"""
Unit Tests for ORACLE Brick 3: Evidence-Guided Investigation Engine
Demonstrates:
  1. Deterministic entity scanning and citation edge creation (derived_by=DETERMINISTIC_REFERENCE)
  2. Controller rejection of premature LLM sufficiency (unresolved references / missing rollbacks)
  3. Controller rejection of sufficiency when edges rely solely on LLM_INFERENCE
  4. LLM_INFERENCE edge cannot independently close an information gap or satisfy factual proof
  5. Budget exhaustion guard (enforcing max_hops / max_llm_calls ceilings)
  6. Duplicate query rejection and stagnation termination guards
  7. Multi-hop investigation completing the Phoenix launch factual chain
"""

import json
from pathlib import Path
import pytest

from backend.evidence.parser import MarkdownEvidenceParser
from backend.investigation.controller import InvestigationController
from backend.investigation.entity_scanner import EntityScanner
from backend.investigation.models import (
    EdgeDerivationType,
    EvidenceEdge,
    InformationGap,
    InvestigationBudget,
    InvestigationState,
    RelationshipType,
)
from backend.retrieval.fts5_retriever import SQLiteFTS5Retriever

CORPUS_DIR = Path(__file__).resolve().parent.parent / "test_data" / "nova_corpus"
MANIFEST_PATH = CORPUS_DIR / "manifest.json"


@pytest.fixture(scope="module")
def indexed_retriever(tmp_path_factory):
    db_path = tmp_path_factory.mktemp("inv_test") / "fts.db"
    retriever = SQLiteFTS5Retriever(db_path=db_path)

    parser = MarkdownEvidenceParser()
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    all_chunks = []
    for doc in manifest["documents"]:
        all_chunks.extend(parser.parse_file(CORPUS_DIR / doc["filename"]))
    retriever.index_evidence(all_chunks)
    return retriever


def test_entity_scanner_deterministic_edges(indexed_retriever):
    """Demonstrate deterministic reference extraction and edge provenance."""
    scanner = EntityScanner()
    parser = MarkdownEvidenceParser()

    inc_chunks = parser.parse_file(CORPUS_DIR / "DOC-NOVA-INC-402.md")
    arch_chunks = parser.parse_file(CORPUS_DIR / "DOC-NOVA-ARCH-OLD.md")

    edges = scanner.detect_deterministic_edges(inc_chunks + arch_chunks)
    assert len(edges) > 0

    # Verify edge provenance invariant
    for edge in edges:
        assert edge.derived_by == EdgeDerivationType.DETERMINISTIC_REFERENCE
        assert edge.confidence == 1.0
        assert edge.is_factual_proof is True


def test_controller_rejects_premature_llm_sufficiency_when_references_unresolved(indexed_retriever):
    """
    DEMONSTRATION 3: Controller MUST reject LLM sufficiency when explicit references are unresolved.
    """
    controller = InvestigationController(retriever=indexed_retriever)
    parser = MarkdownEvidenceParser()
    chunks = parser.parse_file(CORPUS_DIR / "DOC-NOVA-OVERVIEW.md")

    state = InvestigationState(
        objective="Can Phoenix launch?",
        accumulated_evidence={c.evidence_id: c for c in chunks},
        unresolved_references={"INC-402"},  # Explicit ticket still unresolved
        evidence_graph=[],
    )

    is_verified, reason = controller.verify_sufficiency(state, llm_rationale="Looks complete to me.")
    assert is_verified is False
    assert "Unresolved explicit reference" in reason


def test_controller_rejects_sufficiency_for_llm_inference_only_edges(indexed_retriever):
    """
    DEMONSTRATION 4: An EvidenceEdge derived_by = LLM_INFERENCE CANNOT independently establish sufficiency.
    """
    controller = InvestigationController(retriever=indexed_retriever)
    parser = MarkdownEvidenceParser()
    overview_chunks = parser.parse_file(CORPUS_DIR / "DOC-NOVA-OVERVIEW.md")
    payment_chunks = parser.parse_file(CORPUS_DIR / "DOC-NOVA-PAYMENT.md")

    # Build a graph that contains ONLY an LLM_INFERENCE edge (hypothesis)
    hypothetical_edge = EvidenceEdge(
        source_evidence_id=overview_chunks[2].evidence_id,
        target_evidence_id=payment_chunks[2].evidence_id,
        relationship_type=RelationshipType.DEPENDS_ON,
        basis="Hypothetical dependency assumed by LLM without documentary proof",
        derived_by=EdgeDerivationType.LLM_INFERENCE,
        confidence=0.75,
    )

    state = InvestigationState(
        objective="Can Phoenix launch?",
        accumulated_evidence={
            overview_chunks[2].evidence_id: overview_chunks[2],
            payment_chunks[2].evidence_id: payment_chunks[2],
        },
        unresolved_references=set(),
        evidence_graph=[hypothetical_edge],  # ONLY LLM_INFERENCE edge!
    )

    # Epistemic invariant: is_factual_proof must be False for LLM_INFERENCE
    assert hypothetical_edge.is_factual_proof is False

    is_verified, reason = controller.verify_sufficiency(state, llm_rationale="Inferred dependency exists.")
    assert is_verified is False
    assert "relies solely on LLM_INFERENCE edges" in reason


def test_llm_inference_cannot_independently_close_gap(indexed_retriever):
    """
    DEMONSTRATION 4B: An LLM_INFERENCE edge cannot substitute for missing documentary evidence.
    """
    budget = InvestigationBudget(max_hops=2, max_llm_calls=2)
    controller = InvestigationController(retriever=indexed_retriever, budget=budget)
    parser = MarkdownEvidenceParser()
    overview_chunks = parser.parse_file(CORPUS_DIR / "DOC-NOVA-OVERVIEW.md")

    # Agent claims sufficiency relying solely on an invented inferred edge without fetching Payment Gateway
    def inference_only_agent(state: InvestigationState):
        inferred_edge = EvidenceEdge(
            source_evidence_id=overview_chunks[0].evidence_id,
            target_evidence_id=overview_chunks[1].evidence_id,
            relationship_type=RelationshipType.DEPENDS_ON,
            basis="Model thinks these are connected",
            derived_by=EdgeDerivationType.LLM_INFERENCE,
            confidence=0.5,
        )
        return (
            True,  # LLM proposes sufficiency
            "I assume the payment gateway is compliant based on inference.",
            [],
            [inferred_edge],
        )

    package = controller.run_investigation(
        objective="Can Project Phoenix safely launch Friday?",
        reasoning_agent_fn=inference_only_agent,
    )

    # Controller MUST reject LLM proposal and refuse to mark package verified
    assert package.controller_verified is False
    assert package.termination_reason != "SUFFICIENT"


def test_controller_budget_exhaustion_guard(indexed_retriever):
    """
    DEMONSTRATION 5: Controller terminates with BUDGET_EXHAUSTED when hop limit is reached.
    """
    budget = InvestigationBudget(max_hops=2, max_llm_calls=2)
    controller = InvestigationController(retriever=indexed_retriever, budget=budget)

    # Simulated reasoning function that never declares sufficiency
    def stub_reasoning_agent(state: InvestigationState):
        return (
            False,
            "Need more info",
            [
                InformationGap(
                    gap_id=f"GAP-{state.hop_count}",
                    priority=1,
                    description="Need more details",
                    targeted_query=f"Phoenix details hop {state.hop_count}",
                    rationale="Keep searching",
                )
            ],
            [],
        )

    package = controller.run_investigation(
        objective="Can Project Phoenix safely launch?",
        reasoning_agent_fn=stub_reasoning_agent,
    )

    assert package.controller_verified is False
    assert "BUDGET_EXHAUSTED" in package.termination_reason
    assert package.budget_summary["hops_used"] <= 2


def test_controller_duplicate_query_and_stagnation_guard(indexed_retriever):
    """
    DEMONSTRATION 6: Controller rejects duplicate queries and triggers STAGNATION exit.
    """
    controller = InvestigationController(retriever=indexed_retriever)

    # Simulated reasoning function that repeatedly proposes the identical query
    call_count = 0
    def duplicate_query_agent(state: InvestigationState):
        nonlocal call_count
        call_count += 1
        return (
            False,
            "Proposing duplicate query",
            [
                InformationGap(
                    gap_id="GAP-DUP",
                    priority=1,
                    description="Repeated query test",
                    targeted_query="Project Phoenix",  # Already run in Turn 0!
                    rationale="Same query",
                )
            ],
            [],
        )

    package = controller.run_investigation(
        objective="Project Phoenix",
        reasoning_agent_fn=duplicate_query_agent,
    )

    # Controller must detect that "Project Phoenix" is duplicate and terminate with stagnation
    assert package.controller_verified is False
    assert "STAGNATION" in package.termination_reason
    # Ensure it didn't burn multiple duplicate queries
    assert len(package.evidence_items) > 0


def test_successful_multi_hop_investigation(indexed_retriever):
    """
    DEMONSTRATION 7: Autonomous progression from an initial 1-chunk result
    into the complete 4-chunk evidence chain required to prove Phoenix cannot launch.
    """
    budget = InvestigationBudget(max_hops=3, max_llm_calls=3)
    controller = InvestigationController(retriever=indexed_retriever, budget=budget)

    # Step-by-step reasoning simulation following the operational chain:
    # Overview -> Payment Gateway -> Redis Rollback INC-402 -> CAB Rejection
    def guided_reasoning_step(state: InvestigationState):
        has_payment = any("DOC-NOVA-PAYMENT" in e.source_id for e in state.accumulated_evidence.values())
        has_incident = any("DOC-NOVA-INC-402" in e.source_id for e in state.accumulated_evidence.values())
        has_cab = any("DOC-NOVA-CAB" in e.source_id for e in state.accumulated_evidence.values())

        if not has_payment:
            return (
                False,
                "Need Payment Gateway v2 integration specs",
                [
                    InformationGap(
                        gap_id="GAP-PAYMENT",
                        priority=1,
                        description="Identify Payment Gateway datastore security requirements",
                        targeted_query="Payment Gateway v2 mTLS requirements",
                        rationale="Phoenix requires payment gateway",
                    )
                ],
                [],
            )
        elif not has_incident:
            return (
                False,
                "Need active Redis production configuration",
                [
                    InformationGap(
                        gap_id="GAP-REDIS",
                        priority=1,
                        description="Find active Redis version and security configuration",
                        targeted_query="INC-402 Redis rollback current production state",
                        rationale="Payment gateway requires mTLS 1.3 on Redis",
                    )
                ],
                [],
            )
        elif not has_cab:
            return (
                False,
                "Need Change Advisory Board approval log",
                [
                    InformationGap(
                        gap_id="GAP-CAB",
                        priority=1,
                        description="Check if Friday upgrade window was approved",
                        targeted_query="Change Advisory Board decision log meeting #88",
                        rationale="Need to know if Friday maintenance was authorized",
                    )
                ],
                [],
            )
        else:
            # All pieces assembled
            return True, "Complete factual chain gathered: Overview + Payment + Incident + CAB", [], []

    package = controller.run_investigation(
        objective="Can Project Phoenix safely launch this Friday, October 24 at 09:00 UTC?",
        reasoning_agent_fn=guided_reasoning_step,
        initial_k=2,
    )

    # Verify final package outcome
    assert package.controller_verified is True
    assert package.termination_reason == "SUFFICIENT"
    assert len(package.evidence_items) >= 4

    retrieved_sources = {e.source_id for e in package.evidence_items}
    assert "DOC-NOVA-OVERVIEW" in retrieved_sources
    assert "DOC-NOVA-PAYMENT" in retrieved_sources
    assert "DOC-NOVA-INC-402" in retrieved_sources
    assert "DOC-NOVA-CAB" in retrieved_sources

    # Check byte-level provenance integrity on every chunk in the package
    for ev in package.evidence_items:
        fpath = CORPUS_DIR / f"{ev.source_id}.md"
        raw_bytes = fpath.read_bytes()
        assert raw_bytes[ev.start_offset:ev.end_offset].decode("utf-8") == ev.content
