"""
Unit Tests for Brick 3.8: Transitive Dependency Resolution & Fine-Grained Entity State
Validates fixes for the three failure mechanisms identified in INV-HOP-01:
  1. GAP-ROOT-1 cannot prematurely resolve from an individual supporting chunk.
  2. Narrative document presence (INC-402) does not mark incident resolved without active state.
  3. Admitted operational constraints/targets deterministically spawn child InformationGaps.
  4. End-to-end multi-hop transitive propagation retrieves all 4 required chunks for INV-HOP-01.
Zero LLM calls required.
"""

import json
from pathlib import Path
import pytest

from backend.evidence.models import Evidence
from backend.evidence.parser import MarkdownEvidenceParser
from backend.investigation.controller import InvestigationController
from backend.investigation.entity_scanner import EntityScanner
from backend.investigation.models import (
    GapStatus,
    GapType,
    InformationGap,
    InvestigationBudget,
    InvestigationSession,
    InvestigationState,
)
from backend.retrieval.fts5_retriever import SQLiteFTS5Retriever

CORPUS_DIR = Path(__file__).resolve().parent.parent / "test_data" / "nova_corpus"
MANIFEST_PATH = CORPUS_DIR / "manifest.json"


@pytest.fixture(scope="module")
def indexed_retriever(tmp_path_factory):
    db_path = tmp_path_factory.mktemp("transitive_test") / "fts.db"
    retriever = SQLiteFTS5Retriever(db_path=db_path)
    parser = MarkdownEvidenceParser()
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    all_chunks = []
    for doc in manifest["documents"]:
        all_chunks.extend(parser.parse_file(CORPUS_DIR / doc["filename"]))
    retriever.index_evidence(all_chunks)
    return retriever


def test_failure_mechanism_1_gap_root_1_cannot_prematurely_resolve(indexed_retriever):
    """
    FAILURE MECHANISM 1:
    In Brick 3.7, admitting a single chunk on Hop 0.5 caused GAP-ROOT-1 to resolve via fallback branch.
    Verify that GAP-ROOT-1 remains OPEN until all blocking gaps are satisfied and sufficiency is verified.
    """
    controller = InvestigationController(retriever=indexed_retriever)
    session = InvestigationSession(session_id="test-root-gap", objective="Can Phoenix safely launch?")
    controller._derive_and_update_gaps(session, edges=[])

    assert "GAP-ROOT-1" in session.gaps
    assert session.gaps["GAP-ROOT-1"].status == GapStatus.OPEN

    # Simulate admitting an individual supporting chunk
    dummy_ev = Evidence(
        evidence_id="DOC-NOVA-CAB#c003",
        source_id="DOC-NOVA-CAB",
        content="CAB Decision: REJECTED",
        content_hash="abc",
        source_path="CAB.md",
        chunk_index=3,
        start_offset=0,
        end_offset=20,
        created_at="2026-09-02T12:00:00Z",
    )
    session.discovered_evidence[dummy_ev.evidence_id] = dummy_ev

    # Evaluate gap resolution on dummy_ev
    controller._evaluate_gap_resolution(session.gaps["GAP-ROOT-1"], session, [dummy_ev.evidence_id])

    # GAP-ROOT-1 must NOT resolve from a single chunk
    assert session.gaps["GAP-ROOT-1"].status == GapStatus.OPEN
    assert session.gaps["GAP-ROOT-1"].resolved is False


def test_failure_mechanism_2_fine_grained_incident_resolution():
    """
    FAILURE MECHANISM 2:
    Narrative chunks (e.g. incident summary or rollback timeline) must NOT mark an incident token
    resolved without active operational / current production state markers.
    """
    scanner = EntityScanner()
    parser = MarkdownEvidenceParser()
    inc_chunks = parser.parse_file(CORPUS_DIR / "DOC-NOVA-INC-402.md")

    # Chunk 2 is incident summary (memory faults under load)
    c2 = inc_chunks[2]
    # Chunk 3 is remediation narrative (rollback executed)
    c3 = inc_chunks[3]
    # Chunk 4 contains "**Current Production State:** The active production Redis cluster..."
    c4 = inc_chunks[4]

    # Narrative chunks c2 and c3 do NOT satisfy authoritative resolution
    assert scanner.is_authoritative_resolution("INC-402", c2) is False
    assert scanner.is_authoritative_resolution("INC-402", c3) is False

    # Having only narrative chunks leaves INC-402 in unresolved_references
    partial_dict = {c2.evidence_id: c2, c3.evidence_id: c3}
    unres = scanner.find_unresolved_references(partial_dict)
    assert "INC-402" in unres

    # Chunk 4 has the active production state and satisfies authoritative resolution
    assert scanner.is_authoritative_resolution("INC-402", c4) is True

    # With c4 admitted, INC-402 is resolved
    complete_dict = {c2.evidence_id: c2, c3.evidence_id: c3, c4.evidence_id: c4}
    unres_complete = scanner.find_unresolved_references(complete_dict)
    assert "INC-402" not in unres_complete


def test_failure_mechanism_3_generic_evidence_to_gap_propagation(indexed_retriever):
    """
    FAILURE MECHANISM 3:
    Admitted evidence asserting an integration target or constraint must deterministically
    instantiate an InformationGap targeting that subsystem and capability.
    """
    controller = InvestigationController(retriever=indexed_retriever)
    session = InvestigationSession(session_id="test-dep-gap", objective="Can Phoenix launch?")
    parser = MarkdownEvidenceParser()
    payment_chunks = parser.parse_file(CORPUS_DIR / "DOC-NOVA-PAYMENT.md")

    # Admit Payment Gateway v2 Technical Integration Specification (Target: Phoenix Deployment)
    c1 = payment_chunks[1]
    session.discovered_evidence[c1.evidence_id] = c1
    controller._derive_and_update_gaps(session, edges=[])

    # Must spawn integration gap for Payment Gateway v2
    dep_gaps = [g for g in session.gaps.values() if "PAYMENT-GATEWAY" in g.gap_id]
    assert len(dep_gaps) >= 1
    assert dep_gaps[0].gap_type == GapType.PREREQUISITE
    assert dep_gaps[0].is_blocking is True
    assert "requirements failure mode" in dep_gaps[0].targeted_query

    # Admit Chunk 2 with security enforcement constraint
    c2 = payment_chunks[2]
    session.discovered_evidence[c2.evidence_id] = c2
    controller._derive_and_update_gaps(session, edges=[])

    enf_gaps = [g for g in session.gaps.values() if "GAP-ENF" in g.gap_id]
    assert len(enf_gaps) >= 1
    assert "mutual TLS 1.3" in enf_gaps[0].required_information


def test_transitive_propagation_path_inv_hop_01(indexed_retriever):
    """
    END-TO-END TRANSITIVE PROPAGATION:
    Verifies that the multi-hop investigation chain for INV-HOP-01 discovers all 4 required evidence
    chunks (OVERVIEW#c003, CAB#c003, INC-402#c004, PAYMENT#c003) and reaches SUFFICIENT.
    """
    controller = InvestigationController(
        retriever=indexed_retriever,
        budget=InvestigationBudget(max_hops=4, max_llm_calls=4, max_queries=8),
    )

    def mock_guided_reasoning(state: InvestigationState):
        # Even if the LLM proposes an empty list, the controller's open gap ledger
        # must steer retrieval to the missing dependencies!
        return False, "", [], []

    package = controller.run_investigation(
        objective="Can Project Phoenix safely launch this Friday, October 24 at 09:00 UTC?",
        reasoning_agent_fn=mock_guided_reasoning,
        initial_k=8,
    )

    admitted_ids = {e.evidence_id for e in package.evidence_items}

    # Verify all 4 required ground-truth evidence chunks are present
    assert "DOC-NOVA-OVERVIEW#c003" in admitted_ids
    assert "DOC-NOVA-CAB#c003" in admitted_ids
    assert "DOC-NOVA-INC-402#c004" in admitted_ids
    assert "DOC-NOVA-PAYMENT#c003" in admitted_ids

    # Controller must verify sufficiency and terminate SUFFICIENT
    assert package.controller_verified is True
    assert package.termination_reason == "SUFFICIENT"
