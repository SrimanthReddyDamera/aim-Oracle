"""
ORACLE Brick 4.0: Epistemic Evidence Synthesis & Citation Unit Tests
Validates:
1. Verification gates (controller_verified == False -> INSUFFICIENT_EVIDENCE)
2. Blocking gap enforcement
3. Deterministic citation generation with exact byte offsets and SHA-256 hashes
4. Contradiction preservation (no silent collapse)
5. Strict claim-to-evidence grounding (rejection of unbacked LLM claims)
6. Multi-provider synthesis (SQLite doc + Jira ticket + GitHub PR)
7. Complete domain-agnosticism (zero 'if jira:' or 'if github:')
8. Security redaction
"""

import pytest
from backend.evidence.models import Evidence
from backend.investigation.models import (
    EdgeDerivationType,
    EvidenceEdge,
    EvidencePackage,
    GapStatus,
    GapType,
    InformationGap,
    RelationshipType,
)
from backend.synthesis.citations import CitationResolver
from backend.synthesis.models import (
    Claim,
    ClaimType,
    SynthesisResult,
    SynthesisStatus,
    VerificationState,
)
from backend.synthesis.synthesizer import EvidenceSynthesizer


@pytest.fixture
def sample_evidence_pool():
    doc_ev = Evidence(
        evidence_id="DOC-NOVA-PAYMENT#c000",
        source_id="DOC-NOVA-PAYMENT",
        source_type="document",
        uri=None,
        content="# Payment Gateway v2 Technical Integration Specification\nEnforces mTLS 1.3 across all datastore connections.",
        content_hash="hash_doc_1234567890abcdef",
        source_path="docs/DOC-NOVA-PAYMENT.md",
        chunk_index=0,
        start_offset=120,
        end_offset=450,
        metadata={"section": "Overview"},
        created_at="2026-09-01T00:00:00Z",
    )

    jira_ev = Evidence(
        evidence_id="jira:CR-904#c000",
        source_id="CR-904",
        source_type="jira",
        uri="https://starkindustries4229.atlassian.net/browse/CR-904",
        content="Issue Key: CR-904\nCAB unanimously rejected emergency Redis rollback due to missing schema validation.",
        content_hash="hash_jira_abcdef1234567890",
        source_path="https://starkindustries4229.atlassian.net/browse/CR-904",
        chunk_index=0,
        start_offset=0,
        end_offset=105,
        metadata={"status": "Rejected"},
        created_at="2026-09-01T00:00:00Z",
    )

    github_ev = Evidence(
        evidence_id="github:nova/payment-gw#88#c000",
        source_id="nova/payment-gw#88",
        source_type="github",
        uri="https://github.com/nova/payment-gw/pull/88",
        content="Pull Request #88: Payment Gateway mTLS enforcement\nMerged into main by sec-eng.",
        content_hash="hash_github_9876543210fedcba",
        source_path="https://github.com/nova/payment-gw/pull/88",
        chunk_index=0,
        start_offset=0,
        end_offset=95,
        metadata={"state": "merged"},
        created_at="2026-09-01T00:00:00Z",
    )

    return [doc_ev, jira_ev, github_ev]


# 1. Verified EvidencePackage -> authoritative answer
def test_synthesis_success_authoritative_answer(sample_evidence_pool):
    package = EvidencePackage(
        objective="Verify Payment Gateway architecture, CAB decision, and PR 88 status",
        termination_reason="SUFFICIENT",
        controller_verified=True,
        budget_summary={},
        evidence_items=sample_evidence_pool,
        graph_edges=[],
        gap_history=[],
        gaps=[],
    )

    synthesizer = EvidenceSynthesizer()
    result = synthesizer.synthesize(package)

    assert result.status == SynthesisStatus.SUCCESS
    assert len(result.claims) == 3
    assert len(result.citations) == 3
    assert "[1]" in result.final_answer
    assert "Evidence Provenance & Citations" in result.final_answer


# 2. controller_verified=False -> Insufficient Evidence
def test_synthesis_gate_unverified_package(sample_evidence_pool):
    package = EvidencePackage(
        objective="Verify Payment Gateway architecture",
        termination_reason="BUDGET_EXHAUSTED_MAX_HOPS",
        controller_verified=False,
        budget_summary={},
        evidence_items=sample_evidence_pool,
        graph_edges=[],
        gap_history=[],
        gaps=[],
    )

    synthesizer = EvidenceSynthesizer()
    result = synthesizer.synthesize(package)

    assert result.status == SynthesisStatus.INSUFFICIENT_EVIDENCE
    assert result.insufficient_report is not None
    assert len(result.claims) == 0
    assert "Insufficient Evidence" in result.final_answer


# 3. Open blocking gap -> no definitive answer
def test_synthesis_gate_open_blocking_gap(sample_evidence_pool):
    blocking_gap = InformationGap(
        gap_id="GAP-SEC-AUDIT",
        description="Missing security audit signoff",
        required_information="Need confirmation of sec team approval",
        is_blocking=True,
        status=GapStatus.OPEN,
    )

    package = EvidencePackage(
        objective="Verify complete cutover readiness",
        termination_reason="SUFFICIENT",
        controller_verified=True,
        budget_summary={},
        evidence_items=sample_evidence_pool,
        graph_edges=[],
        gap_history=[],
        gaps=[blocking_gap],
    )

    synthesizer = EvidenceSynthesizer()
    result = synthesizer.synthesize(package)

    assert result.status == SynthesisStatus.INSUFFICIENT_EVIDENCE
    assert result.insufficient_report is not None
    assert any("GAP-SEC-AUDIT" == g["gap_id"] for g in result.insufficient_report.open_gaps)


# 4. Every factual claim has evidence mapping
def test_synthesis_all_claims_have_evidence(sample_evidence_pool):
    package = EvidencePackage(
        objective="Verify system specifications",
        termination_reason="SUFFICIENT",
        controller_verified=True,
        budget_summary={},
        evidence_items=sample_evidence_pool,
        graph_edges=[],
        gap_history=[],
        gaps=[],
    )

    synthesizer = EvidenceSynthesizer()
    result = synthesizer.synthesize(package)

    admitted_ids = {e.evidence_id for e in sample_evidence_pool}
    for claim in result.claims:
        assert len(claim.evidence_ids) >= 1
        for eid in claim.evidence_ids:
            assert eid in admitted_ids


# 5. Citation offsets are preserved exactly
def test_citation_offsets_exact_preservation(sample_evidence_pool):
    package = EvidencePackage(
        objective="Verify document offsets",
        termination_reason="SUFFICIENT",
        controller_verified=True,
        budget_summary={},
        evidence_items=sample_evidence_pool,
        graph_edges=[],
        gap_history=[],
        gaps=[],
    )

    synthesizer = EvidenceSynthesizer()
    result = synthesizer.synthesize(package)

    doc_cit = next(c for c in result.citations if c.source_type == "document")
    assert doc_cit.start_offset == 120
    assert doc_cit.end_offset == 450
    assert doc_cit.content_hash == "hash_doc_1234567890abcdef"


# 6. Citation URI comes from Evidence provenance only
def test_citation_uri_from_provenance_only(sample_evidence_pool):
    package = EvidencePackage(
        objective="Verify citation URLs",
        termination_reason="SUFFICIENT",
        controller_verified=True,
        budget_summary={},
        evidence_items=sample_evidence_pool,
        graph_edges=[],
        gap_history=[],
        gaps=[],
    )

    synthesizer = EvidenceSynthesizer()
    result = synthesizer.synthesize(package)

    jira_cit = next(c for c in result.citations if c.source_type == "jira")
    assert jira_cit.source_uri == "https://starkindustries4229.atlassian.net/browse/CR-904"
    gh_cit = next(c for c in result.citations if c.source_type == "github")
    assert gh_cit.source_uri == "https://github.com/nova/payment-gw/pull/88"


# 7. Contradictory evidence cannot silently resolve
def test_contradiction_reconciliation_required(sample_evidence_pool):
    contradict_edge = EvidenceEdge(
        source_evidence_id="DOC-NOVA-PAYMENT#c000",
        target_evidence_id="jira:CR-904#c000",
        relationship_type=RelationshipType.CONTRADICTS,
        basis="Payment doc requires Redis v7, but Jira CR-904 rejected Redis v7 upgrade",
        derived_by=EdgeDerivationType.DETERMINISTIC_REFERENCE,
        confidence=1.0,
    )

    package = EvidencePackage(
        objective="Verify payment architecture decisions",
        termination_reason="SUFFICIENT",
        controller_verified=True,
        budget_summary={},
        evidence_items=sample_evidence_pool,
        graph_edges=[contradict_edge],
        gap_history=[],
        gaps=[],
    )

    synthesizer = EvidenceSynthesizer()
    result = synthesizer.synthesize(package)

    assert result.status == SynthesisStatus.RECONCILIATION_REQUIRED
    assert result.reconciliation_report is not None
    assert len(result.reconciliation_report.contradictions) == 1
    assert "Reconciliation Required" in result.final_answer


# 8. Empty evidence cannot generate claims
def test_empty_evidence_produces_no_claims():
    package = EvidencePackage(
        objective="Empty investigation",
        termination_reason="STAGNATION_NO_GAPS",
        controller_verified=False,
        budget_summary={},
        evidence_items=[],
        graph_edges=[],
        gap_history=[],
        gaps=[],
    )

    synthesizer = EvidenceSynthesizer()
    result = synthesizer.synthesize(package)

    assert result.status == SynthesisStatus.INSUFFICIENT_EVIDENCE
    assert len(result.claims) == 0


# 9. LLM output attempting unsupported claims is rejected
def test_unbacked_llm_claim_rejected(sample_evidence_pool):
    package = EvidencePackage(
        objective="Test hallucination filter",
        termination_reason="SUFFICIENT",
        controller_verified=True,
        budget_summary={},
        evidence_items=sample_evidence_pool,
        graph_edges=[],
        gap_history=[],
        gaps=[],
    )

    def hallucinating_extractor(objective, evidence_items):
        return [
            Claim(
                claim_id="valid_1",
                statement="Verified CAB rejection",
                evidence_ids=["jira:CR-904#c000"],
            ),
            Claim(
                claim_id="fake_1",
                statement="Hallucinated claim without evidence",
                evidence_ids=["NON-EXISTENT-EVIDENCE-ID"],
            ),
        ]

    synthesizer = EvidenceSynthesizer()
    result = synthesizer.synthesize(package, agent_claim_extractor_fn=hallucinating_extractor)

    assert result.status == SynthesisStatus.SUCCESS
    assert len(result.claims) == 1
    assert result.claims[0].claim_id == "valid_1"
    assert "Hallucinated claim" not in result.final_answer


# 10. Deterministic citation generation
def test_deterministic_citation_ordering(sample_evidence_pool):
    package = EvidencePackage(
        objective="Test deterministic ordering",
        termination_reason="SUFFICIENT",
        controller_verified=True,
        budget_summary={},
        evidence_items=sample_evidence_pool,
        graph_edges=[],
        gap_history=[],
        gaps=[],
    )

    synthesizer = EvidenceSynthesizer()
    r1 = synthesizer.synthesize(package)
    r2 = synthesizer.synthesize(package)

    assert [c.citation_id for c in r1.citations] == [c.citation_id for c in r2.citations]
    assert [c.evidence_id for c in r1.citations] == [c.evidence_id for c in r2.citations]


# 11. Multiple providers can contribute to one answer
def test_multi_provider_citations(sample_evidence_pool):
    package = EvidencePackage(
        objective="Test multi-provider fusion",
        termination_reason="SUFFICIENT",
        controller_verified=True,
        budget_summary={},
        evidence_items=sample_evidence_pool,
        graph_edges=[],
        gap_history=[],
        gaps=[],
    )

    synthesizer = EvidenceSynthesizer()
    result = synthesizer.synthesize(package)

    source_types = {c.source_type for c in result.citations}
    assert source_types == {"document", "jira", "github"}


# 12. Jira evidence produces a Jira citation without Jira-specific synthesis logic
def test_generic_jira_citation(sample_evidence_pool):
    jira_item = sample_evidence_pool[1]
    cit = CitationResolver.resolve_citation(jira_item, citation_index=1)

    assert cit.citation_id == "[1]"
    assert cit.source_type == "jira"
    assert "JIRA: CR-904" in cit.display_reference
    assert "https://starkindustries4229.atlassian.net/browse/CR-904" in cit.source_uri


# 13. GitHub evidence produces a GitHub citation without GitHub-specific synthesis logic
def test_generic_github_citation(sample_evidence_pool):
    gh_item = sample_evidence_pool[2]
    cit = CitationResolver.resolve_citation(gh_item, citation_index=2)

    assert cit.citation_id == "[2]"
    assert cit.source_type == "github"
    assert "GITHUB: nova/payment-gw#88" in cit.display_reference
    assert "https://github.com/nova/payment-gw/pull/88" in cit.source_uri


# 14. Causal chain preservation
def test_causal_chain_preservation(sample_evidence_pool):
    # Edge: Payment Gateway depends on PR 88
    depends_edge = EvidenceEdge(
        source_evidence_id="DOC-NOVA-PAYMENT#c000",
        target_evidence_id="github:nova/payment-gw#88#c000",
        relationship_type=RelationshipType.DEPENDS_ON,
        basis="Spec requires mTLS code landed in PR 88",
        derived_by=EdgeDerivationType.DETERMINISTIC_REFERENCE,
        confidence=1.0,
    )

    package = EvidencePackage(
        objective="Verify dependency link",
        termination_reason="SUFFICIENT",
        controller_verified=True,
        budget_summary={},
        evidence_items=sample_evidence_pool,
        graph_edges=[depends_edge],
        gap_history=[],
        gaps=[],
    )

    synthesizer = EvidenceSynthesizer()
    result = synthesizer.synthesize(package)

    doc_claim = next(c for c in result.claims if "DOC-NOVA-PAYMENT#c000" in c.evidence_ids)
    gh_claim = next(c for c in result.claims if "github:nova/payment-gw#88#c000" in c.evidence_ids)

    assert gh_claim.claim_id in doc_claim.causal_predecessors
    assert f"Prequisite: {gh_claim.claim_id}" in result.final_answer


# 15. Security redaction in synthesis
def test_zero_secret_exposure_in_synthesis(sample_evidence_pool):
    # Injected token into content
    sensitive_ev = Evidence(
        evidence_id="jira:SEC-1#c000",
        source_id="SEC-1",
        source_type="jira",
        uri="https://starkindustries4229.atlassian.net/browse/SEC-1",
        content="Incident ticket: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9 token leaked in logs.",
        content_hash="hash_sec_112233",
        source_path="https://starkindustries4229.atlassian.net/browse/SEC-1",
        chunk_index=0,
        start_offset=0,
        end_offset=80,
        metadata={},
        created_at="2026-09-01T00:00:00Z",
    )

    package = EvidencePackage(
        objective="Verify secret handling",
        termination_reason="SUFFICIENT",
        controller_verified=True,
        budget_summary={},
        evidence_items=[sensitive_ev],
        graph_edges=[],
        gap_history=[],
        gaps=[],
    )

    synthesizer = EvidenceSynthesizer()
    result = synthesizer.synthesize(package)

    assert "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" not in result.final_answer
    assert "***REDACTED***" in result.final_answer


# -----------------------------------------------------------------------------
# BRICK 4.1 REGRESSION TESTS (Surgically verifying remediated defects)
# -----------------------------------------------------------------------------

def test_regression_orphaned_gap_dep_payment_gateway():
    """
    REGRESSION TEST (Defect 1):
    Verifies that when an investigation satisfies the requirements of derived prerequisite
    gaps (specifically GAP-DEP-PAYMENT-GATEWAY), the controller transitions that gap to
    RESOLVED so that EvidenceSynthesizer does not abort with INSUFFICIENT_EVIDENCE.
    """
    from backend.evidence.parser import MarkdownEvidenceParser
    from backend.retrieval.fts5_retriever import SQLiteFTS5Retriever
    from backend.investigation.controller import InvestigationController
    from backend.investigation.models import InvestigationBudget
    from pathlib import Path
    import json

    corpus_dir = Path("tests/test_data/nova_corpus")
    parser = MarkdownEvidenceParser()
    manifest = json.loads((corpus_dir / "manifest.json").read_text(encoding="utf-8"))
    all_chunks = []
    for doc in manifest["documents"]:
        all_chunks.extend(parser.parse_file(corpus_dir / doc["filename"]))

    retriever = SQLiteFTS5Retriever(":memory:")
    retriever.index_evidence(all_chunks)

    controller = InvestigationController(
        retriever=retriever,
        budget=InvestigationBudget(max_hops=2, max_llm_calls=2),
    )
    objective = "Verify Project Phoenix cutover prerequisites and payment gateway requirements"
    package = controller.run_investigation(
        objective=objective,
        reasoning_agent_fn=lambda s: (True, "Verified from corpus", [], []),
        initial_k=4,
    )

    assert package.controller_verified is True
    # Confirm GAP-DEP-PAYMENT-GATEWAY was transitioned to RESOLVED
    dep_gap = next((g for g in package.gaps if "PAYMENT-GATEWAY" in g.gap_id), None)
    assert dep_gap is not None
    assert dep_gap.status == GapStatus.RESOLVED

    # Synthesizer must succeed with definitive claims
    synthesizer = EvidenceSynthesizer()
    result = synthesizer.synthesize(package)
    assert result.status == SynthesisStatus.SUCCESS
    assert len(result.claims) > 0


def test_regression_empty_evidence_candidate_claim(sample_evidence_pool):
    """
    REGRESSION TEST (Defect 2):
    Verifies that candidate claims entering with evidence_ids=[] do not trigger
    an unhandled Pydantic ValidationError and are gracefully rejected by the Grounding Gate.
    """
    dummy_ev = sample_evidence_pool[0]
    package = EvidencePackage(
        objective="Test candidate claim validation",
        termination_reason="SUFFICIENT",
        controller_verified=True,
        budget_summary={},
        evidence_items=[dummy_ev],
        graph_edges=[],
        gap_history=[],
        gaps=[],
    )

    def extractor_with_empty_ids(obj, evs):
        return [
            Claim(
                claim_id="valid_c",
                statement="Verified statement",
                evidence_ids=[dummy_ev.evidence_id],
            ),
            Claim(
                claim_id="empty_ids_c",
                statement="Unsupported statement with empty evidence list",
                evidence_ids=[],  # Candidate claim with empty list
            ),
        ]

    synthesizer = EvidenceSynthesizer()
    result = synthesizer.synthesize(package, agent_claim_extractor_fn=extractor_with_empty_ids)

    assert result.status == SynthesisStatus.SUCCESS
    assert len(result.claims) == 1
    assert result.claims[0].claim_id == "valid_c"
    assert "Unsupported statement" not in result.final_answer


def test_regression_adversarial_objective_header_sanitization():
    """
    REGRESSION TEST (Defect 3):
    Verifies that raw user objectives with Markdown formatting or injection attempts
    are properly sanitized and length-capped in Markdown headings.
    """
    malicious_objective = "### Heading Injection! [Malicious Link](http://attacker.com) *bold* `code` and very long text " * 5

    package = EvidencePackage(
        objective=malicious_objective,
        termination_reason="BUDGET_EXHAUSTED_MAX_HOPS",
        controller_verified=False,
        budget_summary={},
        evidence_items=[],
        graph_edges=[],
        gap_history=[],
        gaps=[],
    )

    synthesizer = EvidenceSynthesizer()
    result = synthesizer.synthesize(package)

    assert result.status == SynthesisStatus.INSUFFICIENT_EVIDENCE
    # Check that the raw markdown syntax was sanitized in the heading line
    heading_line = [line for line in result.final_answer.split("\n") if line.startswith("## Insufficient Evidence:")][0]
    assert len(heading_line) <= 120
    assert "###" not in heading_line[3:]  # No nested markdown headings
    assert "\\#\\#\\#" in heading_line or "\\*" in heading_line or "\\[" in heading_line


def test_regression_secret_leakage_in_citation_preview_and_serialization():
    """
    REGRESSION TEST (Defect A):
    Verifies that secrets (GitHub PATs, Bearer tokens, passwords) embedded in raw Evidence
    are strictly redacted from Citation.content_preview and cannot leak into serialized
    SynthesisResult.model_dump_json().
    """
    fake_pat = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"
    fake_bearer = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    ev = Evidence(
        evidence_id="EV-SEC-01",
        source_id="SECRET-TICKET-99",
        source_type="jira",
        uri=f"https://internal.jira.net/browse/SEC-99?token={fake_pat}",
        content=f"Secret credentials: PAT={fake_pat} and Header={fake_bearer}",
        content_hash="h_sec99",
        source_path="browse/SEC-99",
        chunk_index=0,
        start_offset=0,
        end_offset=95,
        metadata={},
        created_at="2026-09-01T00:00:00Z",
    )
    package = EvidencePackage(
        objective="Verify credential redaction in citations and JSON export",
        termination_reason="SUFFICIENT",
        controller_verified=True,
        budget_summary={},
        evidence_items=[ev],
        graph_edges=[],
        gap_history=[],
        gaps=[],
    )

    synthesizer = EvidenceSynthesizer()
    res = synthesizer.synthesize(package)

    # 1. Verify Citation object fields directly
    assert len(res.citations) == 1
    cit = res.citations[0]
    assert fake_pat not in cit.content_preview
    assert fake_bearer not in cit.content_preview
    assert fake_pat not in (cit.source_uri or "")
    assert fake_pat not in cit.display_reference
    assert "***REDACTED_PAT***" in cit.content_preview or "***REDACTED***" in cit.content_preview

    # 2. Verify serialized model JSON export
    json_export = res.model_dump_json()
    assert fake_pat not in json_export, "PAT leaked in SynthesisResult.model_dump_json()!"
    assert fake_bearer not in json_export, "Bearer token leaked in SynthesisResult.model_dump_json()!"


