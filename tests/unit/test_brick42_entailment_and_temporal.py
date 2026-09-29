"""
BRICK 4.2 ADVERSARIAL TEST SUITE
================================
Tests for:
1. Semantic Entailment Verification (negation inversion, numerical distortion, entity substitution, verbatim anchors).
2. Cross-Provider Temporal Conflict & Staleness Resolution (SUPERSEDES, CONTRADICTS).
"""

import pytest
from backend.evidence.models import Evidence
from backend.investigation.entity_scanner import EntityScanner
from backend.investigation.models import (
    EdgeDerivationType,
    EvidenceEdge,
    EvidencePackage,
    RelationshipType,
)
from backend.investigation.temporal_scanner import TemporalConflictScanner
from backend.synthesis.entailment import EntailmentVerifier
from backend.synthesis.models import Claim, SynthesisStatus, VerificationState
from backend.synthesis.synthesizer import EvidenceSynthesizer


@pytest.fixture
def base_evidence():
    return Evidence(
        evidence_id="EV-PAY-01",
        source_id="DOC-PAYMENT-V2",
        source_type="document",
        uri="file:///payment.md",
        content="Payment gateway v2 strictly enforces mutual TLS 1.3 on port 8443 with connection pool limit of 50.",
        content_hash="hash_pay",
        source_path="/payment.md",
        chunk_index=0,
        start_offset=0,
        end_offset=100,
        metadata={},
        created_at="2026-09-01T00:00:00Z",
    )


def test_adversarial_negation_inversion_rejected(base_evidence):
    """
    Verifies that candidate claims reversing the negation of evidence
    (e.g., asserting TLS is NOT enforced) are strictly rejected by the Entailment Gate.
    """
    package = EvidencePackage(
        objective="Verify payment gateway security",
        termination_reason="SUFFICIENT",
        controller_verified=True,
        budget_summary={},
        evidence_items=[base_evidence],
        graph_edges=[],
        gap_history=[],
        gaps=[],
    )

    # Adversarial candidate claim reverses negation
    def adversarial_negation_extractor(obj, evs):
        return [
            Claim(
                claim_id="c_reversed",
                statement="Payment gateway does NOT enforce mutual TLS 1.3 on port 8443.",
                evidence_ids=["EV-PAY-01"],
            )
        ]

    synthesizer = EvidenceSynthesizer()
    res = synthesizer.synthesize(package, agent_claim_extractor_fn=adversarial_negation_extractor)

    # Entailment Gate must reject the claim -> 0 verified claims -> INSUFFICIENT_EVIDENCE
    assert res.status == SynthesisStatus.INSUFFICIENT_EVIDENCE
    assert len(res.claims) == 0
    assert "Payment gateway does NOT enforce" not in res.final_answer


def test_adversarial_numerical_hallucination_rejected(base_evidence):
    """
    Verifies that claims asserting ungrounded numerical quantities or ports
    (e.g. port 80 or 5000 connections) are rejected.
    """
    package = EvidencePackage(
        objective="Verify payment gateway limits",
        termination_reason="SUFFICIENT",
        controller_verified=True,
        budget_summary={},
        evidence_items=[base_evidence],
        graph_edges=[],
        gap_history=[],
        gaps=[],
    )

    def adversarial_num_extractor(obj, evs):
        return [
            Claim(
                claim_id="c_distorted",
                statement="Payment gateway connection pool limit is set to 5000 connections.",
                evidence_ids=["EV-PAY-01"],
            )
        ]

    synthesizer = EvidenceSynthesizer()
    res = synthesizer.synthesize(package, agent_claim_extractor_fn=adversarial_num_extractor)

    assert res.status == SynthesisStatus.INSUFFICIENT_EVIDENCE
    assert len(res.claims) == 0


def test_adversarial_entity_substitution_rejected(base_evidence):
    """
    Verifies that claims introducing completely foreign entities
    not present in the evidence are rejected.
    """
    package = EvidencePackage(
        objective="Verify payment gateway vendor",
        termination_reason="SUFFICIENT",
        controller_verified=True,
        budget_summary={},
        evidence_items=[base_evidence],
        graph_edges=[],
        gap_history=[],
        gaps=[],
    )

    def adversarial_entity_extractor(obj, evs):
        return [
            Claim(
                claim_id="c_foreign",
                statement="PayPal service and Worldpay gateway handle mutual TLS.",
                evidence_ids=["EV-PAY-01"],
            )
        ]

    synthesizer = EvidenceSynthesizer()
    res = synthesizer.synthesize(package, agent_claim_extractor_fn=adversarial_entity_extractor)

    assert res.status == SynthesisStatus.INSUFFICIENT_EVIDENCE
    assert len(res.claims) == 0


def test_verbatim_anchor_enforcement(base_evidence):
    """
    Verifies that a valid verbatim anchor allows claim admittance,
    whereas an ungrounded or fabricated anchor causes rejection.
    """
    package = EvidencePackage(
        objective="Verify mutual TLS",
        termination_reason="SUFFICIENT",
        controller_verified=True,
        budget_summary={},
        evidence_items=[base_evidence],
        graph_edges=[],
        gap_history=[],
        gaps=[],
    )

    # 1. Valid anchor
    valid_claim = Claim(
        claim_id="c_anchored",
        statement="Payment gateway v2 strictly enforces mutual TLS 1.3.",
        evidence_ids=["EV-PAY-01"],
        verbatim_anchor="Payment gateway v2 strictly enforces mutual TLS 1.3",
    )
    res_valid = EvidenceSynthesizer().synthesize(package, agent_claim_extractor_fn=lambda o, e: [valid_claim])
    assert res_valid.status == SynthesisStatus.SUCCESS
    assert len(res_valid.claims) == 1

    # 2. Fabricated anchor
    bad_claim = Claim(
        claim_id="c_bad_anchor",
        statement="Payment gateway v2 strictly enforces mutual TLS 1.3.",
        evidence_ids=["EV-PAY-01"],
        verbatim_anchor="Payment gateway is unencrypted and free to access",
    )
    res_bad = EvidenceSynthesizer().synthesize(package, agent_claim_extractor_fn=lambda o, e: [bad_claim])
    assert res_bad.status == SynthesisStatus.INSUFFICIENT_EVIDENCE
    assert len(res_bad.claims) == 0


def test_cross_provider_temporal_supersession():
    """
    Verifies that a newer evidence item from GitHub supersedes an older
    contradictory state in Jira, dropping the stale claim.
    """
    ev_jira_old = Evidence(
        evidence_id="JIRA-100",
        source_id="OPS-100",
        source_type="jira",
        uri="https://jira.corp/OPS-100",
        content="Deployment status: auth-gateway is DEPLOYED and ACTIVE in production cluster.",
        content_hash="hash_j",
        source_path="OPS-100",
        chunk_index=0,
        start_offset=0,
        end_offset=70,
        metadata={},
        created_at="2024-01-15T10:00:00Z",  # Older
    )
    ev_gh_new = Evidence(
        evidence_id="GH-200",
        source_id="commit-200",
        source_type="github",
        uri="https://github.com/org/repo/commit/200",
        content="Reverted auth-gateway; service is DISABLED and shutdown due to null pointer panic.",
        content_hash="hash_g",
        source_path="commit-200",
        chunk_index=0,
        start_offset=0,
        end_offset=75,
        metadata={},
        created_at="2026-09-01T12:00:00Z",  # Newer
    )

    scanner = EntityScanner()
    edges = scanner.detect_deterministic_edges([ev_jira_old, ev_gh_new])

    # Must detect SUPERSEDES edge from GH-200 to JIRA-100
    supersedes_edges = [e for e in edges if e.relationship_type == RelationshipType.SUPERSEDES]
    assert len(supersedes_edges) >= 1
    assert any(e.source_evidence_id == "GH-200" and e.target_evidence_id == "JIRA-100" for e in supersedes_edges)

    package = EvidencePackage(
        objective="What is the current status of auth-gateway?",
        termination_reason="SUFFICIENT",
        controller_verified=True,
        budget_summary={},
        evidence_items=[ev_jira_old, ev_gh_new],
        graph_edges=edges,
        gap_history=[],
        gaps=[],
    )

    synthesizer = EvidenceSynthesizer()
    res = synthesizer.synthesize(package)

    assert res.status == SynthesisStatus.SUCCESS
    # Final answer must only contain the active newer claim (GH-200) and omit the stale claim (JIRA-100)
    assert len(res.claims) == 1
    assert res.claims[0].evidence_ids == ["GH-200"]
    assert "DISABLED and shutdown" in res.claims[0].statement
    assert "DEPLOYED and ACTIVE" not in res.final_answer


def test_concurrent_disputed_conflict_forces_reconciliation():
    """
    Verifies that when contradictory evidence shares identical timestamps or cannot
    be temporally ordered, Gate 2 forces RECONCILIATION_REQUIRED.
    """
    ev_1 = Evidence(
        evidence_id="EV-1",
        source_id="TICKET-1",
        source_type="jira",
        uri="https://jira.corp/1",
        content="Incident: auth-gateway is DEPLOYED and ACTIVE.",
        content_hash="h1",
        source_path="1",
        chunk_index=0,
        start_offset=0,
        end_offset=45,
        metadata={},
        created_at="2026-09-01T12:00:00Z",
    )
    ev_2 = Evidence(
        evidence_id="EV-2",
        source_id="TICKET-2",
        source_type="jira",
        uri="https://jira.corp/2",
        content="Incident: auth-gateway is DISABLED and shutdown.",
        content_hash="h2",
        source_path="2",
        chunk_index=0,
        start_offset=0,
        end_offset=45,
        metadata={},
        created_at="2026-09-01T12:00:00Z",  # Identical timestamp
    )

    scanner = EntityScanner()
    edges = scanner.detect_deterministic_edges([ev_1, ev_2])

    contra_edges = [e for e in edges if e.relationship_type == RelationshipType.CONTRADICTS]
    assert len(contra_edges) >= 1

    package = EvidencePackage(
        objective="Determine auth-gateway state",
        termination_reason="SUFFICIENT",
        controller_verified=True,
        budget_summary={},
        evidence_items=[ev_1, ev_2],
        graph_edges=edges,
        gap_history=[],
        gaps=[],
    )

    synthesizer = EvidenceSynthesizer()
    res = synthesizer.synthesize(package)

    assert res.status == SynthesisStatus.RECONCILIATION_REQUIRED
    assert res.reconciliation_report is not None


def test_adversarial_entity_metric_cross_attribution_rejected():
    """
    REGRESSION TEST:
    Verifies that claims attempting cross-entity metric/port shuffling
    (binding an entity from sentence 1 with a number from sentence 2)
    are rejected by the local co-occurrence check in EntailmentVerifier.
    """
    ev = Evidence(
        evidence_id="EV-MULTI-01",
        source_id="DOC-MULTI",
        source_type="document",
        uri="file:///multi.md",
        content="Service alpha-gateway is deployed on port 8080. Service beta-worker runs on port 9090.",
        content_hash="hash_m",
        source_path="/multi.md",
        chunk_index=0,
        start_offset=0,
        end_offset=86,
        metadata={},
        created_at="2026-09-01T00:00:00Z",
    )
    package = EvidencePackage(
        objective="Verify service ports",
        termination_reason="SUFFICIENT",
        controller_verified=True,
        budget_summary={},
        evidence_items=[ev],
        graph_edges=[],
        gap_history=[],
        gaps=[],
    )

    # Shuffled attribution: binds alpha-gateway to 9090
    claim = Claim(
        claim_id="c_shuffled",
        statement="Service alpha-gateway runs on port 9090.",
        evidence_ids=["EV-MULTI-01"],
    )

    res = EvidenceSynthesizer().synthesize(package, agent_claim_extractor_fn=lambda o, e: [claim])
    assert res.status == SynthesisStatus.INSUFFICIENT_EVIDENCE
    assert len(res.claims) == 0


def test_adversarial_antonym_contradiction_rejected():
    """
    REGRESSION TEST:
    Verifies that claims asserting antonym opposites of evidence
    (e.g., asserting 'secure' when evidence asserts 'vulnerable')
    are rejected as semantic contradictions.
    """
    ev = Evidence(
        evidence_id="EV-SEC-01",
        source_id="DOC-VULN",
        source_type="document",
        uri="file:///sec.md",
        content="The core authentication service is vulnerable to remote code execution.",
        content_hash="hash_v",
        source_path="/sec.md",
        chunk_index=0,
        start_offset=0,
        end_offset=75,
        metadata={},
        created_at="2026-09-01T00:00:00Z",
    )
    package = EvidencePackage(
        objective="Verify security state",
        termination_reason="SUFFICIENT",
        controller_verified=True,
        budget_summary={},
        evidence_items=[ev],
        graph_edges=[],
        gap_history=[],
        gaps=[],
    )

    claim = Claim(
        claim_id="c_antonym",
        statement="The core authentication service is secure against remote code execution.",
        evidence_ids=["EV-SEC-01"],
    )

    res = EvidenceSynthesizer().synthesize(package, agent_claim_extractor_fn=lambda o, e: [claim])
    assert res.status == SynthesisStatus.INSUFFICIENT_EVIDENCE
    assert len(res.claims) == 0


def test_space_separated_entity_temporal_supersession():
    """
    REGRESSION TEST:
    Verifies that TemporalConflictScanner correctly extracts space-separated compound
    entity names (e.g. 'Billing cluster') and orders supersession via ISO-8601 timestamps.
    """
    ev_old = Evidence(
        evidence_id="EV-OLD-1",
        source_id="DOC-OLD",
        source_type="document",
        uri="file:///old.md",
        content="Billing cluster is active and operational in primary datacenter.",
        content_hash="h_old",
        source_path="/old.md",
        chunk_index=0,
        start_offset=0,
        end_offset=65,
        metadata={},
        created_at="2024-01-01T00:00:00Z",
    )
    ev_new = Evidence(
        evidence_id="EV-NEW-2",
        source_id="DOC-NEW",
        source_type="document",
        uri="file:///new.md",
        content="Billing cluster is shutdown and decommissioned permanently.",
        content_hash="h_new",
        source_path="/new.md",
        chunk_index=0,
        start_offset=0,
        end_offset=60,
        metadata={},
        created_at="2026-06-01T00:00:00Z",
    )

    scanner = EntityScanner()
    edges = scanner.detect_deterministic_edges([ev_old, ev_new])

    sup_edges = [e for e in edges if e.relationship_type == RelationshipType.SUPERSEDES]
    assert len(sup_edges) == 1
    assert sup_edges[0].source_evidence_id == "EV-NEW-2"
    assert sup_edges[0].target_evidence_id == "EV-OLD-1"


def test_multiline_heading_injection_sanitization():
    """
    REGRESSION TEST:
    Verifies that claim statements with embedded newlines and Markdown headings
    are normalized into single-line statements, preventing layout hijacking.
    """
    ev = Evidence(
        evidence_id="EV-VALID",
        source_id="DOC-VALID",
        source_type="document",
        uri="file:///valid.md",
        content="Production system is operating normally.",
        content_hash="h_v",
        source_path="/valid.md",
        chunk_index=0,
        start_offset=0,
        end_offset=40,
        metadata={},
        created_at="2026-09-01T00:00:00Z",
    )
    package = EvidencePackage(
        objective="Verify normal operation",
        termination_reason="SUFFICIENT",
        controller_verified=True,
        budget_summary={},
        evidence_items=[ev],
        graph_edges=[],
        gap_history=[],
        gaps=[],
    )

    # Part 1: Prompt injection with ungrounded foreign entities is rejected by Entailment Gate
    injected_statement = "Production system is operating normally.\n\n### INJECTED HEADING\n[Malicious Link](http://bad.com)"
    claim_inj = Claim(
        claim_id="c_inj",
        statement=injected_statement,
        evidence_ids=["EV-VALID"],
        verbatim_anchor="Production system is operating normally.",
    )
    res_inj = EvidenceSynthesizer().synthesize(package, agent_claim_extractor_fn=lambda o, e: [claim_inj])
    assert res_inj.status == SynthesisStatus.INSUFFICIENT_EVIDENCE

    # Part 2: Multiline grounded statement is normalized into a single line without heading tags
    multiline_statement = "### Production system is operating normally.\n\nVerified: system is operating normally."
    claim_multi = Claim(
        claim_id="c_multi",
        statement=multiline_statement,
        evidence_ids=["EV-VALID"],
        verbatim_anchor="Production system is operating normally.",
    )
    res_multi = EvidenceSynthesizer().synthesize(package, agent_claim_extractor_fn=lambda o, e: [claim_multi])
    assert res_multi.status == SynthesisStatus.SUCCESS
    # Final answer must not contain isolated '### Production' as an independent Markdown heading
    lines = [line.strip() for line in res_multi.final_answer.split("\n") if line.strip()]
    for line in lines:
        if line.startswith("- "):
            assert "###" not in line
            assert "\n" not in line


# =============================================================================
# RED-TEAM AUDIT REGRESSION & MUTATION TESTS (BRICK 4.2 REMEDIATION)
# =============================================================================

def test_regression_vuln1_prefix_negation_reversal_and_mutations():
    """
    REGRESSION & MUTATION SUITE (VULN-1):
    Verifies that claims attempting to reverse negative assertions by selecting
    positive verbatim anchors are strictly rejected across various negation patterns.
    """
    # 1. Exact Exploit: 'TLS is not enforced in production' -> 'TLS is enforced in production'
    ev1 = Evidence(
        evidence_id="EV-NEG-1",
        source_id="DOC-NEG-1",
        source_type="document",
        uri="file:///tls.md",
        content="TLS is not enforced in production.",
        content_hash="h1",
        source_path="/tls.md",
        chunk_index=0,
        start_offset=0,
        end_offset=34,
        metadata={},
        created_at="2026-09-01T00:00:00Z",
    )
    claim1 = Claim(
        claim_id="c1",
        statement="TLS is enforced in production.",
        evidence_ids=["EV-NEG-1"],
        verbatim_anchor="enforced in production",
    )
    is_entailed, reason = EntailmentVerifier.verify_claim_entailment(claim1, ev1)
    assert not is_entailed
    assert "Anchor prefix negation dropped" in (reason or "")

    # 2. Mutation A: 'without mutual TLS' -> 'with mutual TLS'
    ev2 = Evidence(
        evidence_id="EV-NEG-2",
        source_id="DOC-NEG-2",
        source_type="document",
        uri="file:///auth.md",
        content="Service operates without mutual TLS authorization.",
        content_hash="h2",
        source_path="/auth.md",
        chunk_index=0,
        start_offset=0,
        end_offset=48,
        metadata={},
        created_at="2026-09-01T00:00:00Z",
    )
    claim2 = Claim(
        claim_id="c2",
        statement="Service operates with mutual TLS authorization.",
        evidence_ids=["EV-NEG-2"],
        verbatim_anchor="mutual TLS authorization",
    )
    is_entailed2, reason2 = EntailmentVerifier.verify_claim_entailment(claim2, ev2)
    assert not is_entailed2
    assert "Anchor prefix negation dropped" in (reason2 or "")

    # 3. Mutation B: 'never active in production' -> 'active in production'
    ev3 = Evidence(
        evidence_id="EV-NEG-3",
        source_id="DOC-NEG-3",
        source_type="document",
        uri="file:///stat.md",
        content="Worker daemon is never active in production cluster.",
        content_hash="h3",
        source_path="/stat.md",
        chunk_index=0,
        start_offset=0,
        end_offset=50,
        metadata={},
        created_at="2026-09-01T00:00:00Z",
    )
    claim3 = Claim(
        claim_id="c3",
        statement="Worker daemon is active in production cluster.",
        evidence_ids=["EV-NEG-3"],
        verbatim_anchor="active in production cluster",
    )
    is_entailed3, _ = EntailmentVerifier.verify_claim_entailment(claim3, ev3)
    assert not is_entailed3


def test_regression_vuln2_scope_environment_inversion_and_mutations():
    """
    REGRESSION & MUTATION SUITE (VULN-2):
    Verifies that claims altering or omitting environment scope qualifiers
    (staging, dev, test, production) fail entailment.
    """
    # 1. Exact Exploit: staging limit asserted as production limit
    ev1 = Evidence(
        evidence_id="EV-SCOPE-1",
        source_id="DOC-SCOPE-1",
        source_type="document",
        uri="file:///lim.md",
        content="The payment gateway limit is 100 requests/minute for staging environment only.",
        content_hash="h1",
        source_path="/lim.md",
        chunk_index=0,
        start_offset=0,
        end_offset=80,
        metadata={},
        created_at="2026-09-01T00:00:00Z",
    )
    claim1 = Claim(
        claim_id="c1",
        statement="The payment gateway limit is 100 requests/minute in production.",
        evidence_ids=["EV-SCOPE-1"],
        verbatim_anchor="The payment gateway limit is 100 requests/minute",
    )
    is_entailed, reason = EntailmentVerifier.verify_claim_entailment(claim1, ev1)
    assert not is_entailed
    assert "Scope mismatch" in (reason or "")

    # 2. Mutation A: dropping staging scope into an unqualified global assertion
    claim2 = Claim(
        claim_id="c2",
        statement="The payment gateway limit is 100 requests/minute.",
        evidence_ids=["EV-SCOPE-1"],
        verbatim_anchor="The payment gateway limit is 100 requests/minute",
    )
    is_entailed2, reason2 = EntailmentVerifier.verify_claim_entailment(claim2, ev1)
    assert not is_entailed2
    assert "Scope drop" in (reason2 or "")

    # 3. Mutation B: local sandbox asserted as canary
    ev3 = Evidence(
        evidence_id="EV-SCOPE-3",
        source_id="DOC-SCOPE-3",
        source_type="document",
        uri="file:///box.md",
        content="Database credentials are hardcoded for local sandbox testing.",
        content_hash="h3",
        source_path="/box.md",
        chunk_index=0,
        start_offset=0,
        end_offset=60,
        metadata={},
        created_at="2026-09-01T00:00:00Z",
    )
    claim3 = Claim(
        claim_id="c3",
        statement="Database credentials are hardcoded for canary testing.",
        evidence_ids=["EV-SCOPE-3"],
    )
    is_entailed3, _ = EntailmentVerifier.verify_claim_entailment(claim3, ev3)
    assert not is_entailed3


def test_regression_vuln3_compound_claim_decomposition():
    """
    REGRESSION & MUTATION SUITE (VULN-3):
    Verifies that compound claims containing both grounded and ungrounded clauses
    are decomposed and rejected if any material clause is unsupported.
    """
    ev = Evidence(
        evidence_id="EV-PG-1",
        source_id="DOC-PG-1",
        source_type="document",
        uri="file:///pg.md",
        content="PostgreSQL database is configured with replication on primary node.",
        content_hash="h1",
        source_path="/pg.md",
        chunk_index=0,
        start_offset=0,
        end_offset=65,
        metadata={},
        created_at="2026-09-01T00:00:00Z",
    )

    # 1. Exact Exploit: valid replication clause + ungrounded automated failover clause
    claim1 = Claim(
        claim_id="c1",
        statement="PostgreSQL database is configured with replication on primary node and automated failover is enabled.",
        evidence_ids=["EV-PG-1"],
        verbatim_anchor="PostgreSQL database is configured with replication",
    )
    is_entailed, reason = EntailmentVerifier.verify_claim_entailment(claim1, ev)
    assert not is_entailed
    assert "Unsupported compound clause" in (reason or "")

    # 2. Mutation A: 'moreover backup retention is configured'
    claim2 = Claim(
        claim_id="c2",
        statement="PostgreSQL database is configured with replication; moreover backup retention is configured.",
        evidence_ids=["EV-PG-1"],
        verbatim_anchor="PostgreSQL database is configured with replication",
    )
    is_entailed2, _ = EntailmentVerifier.verify_claim_entailment(claim2, ev)
    assert not is_entailed2

    # 3. Legitimate fully supported compound statement passes
    claim3 = Claim(
        claim_id="c3",
        statement="PostgreSQL database is configured with replication and running on primary node.",
        evidence_ids=["EV-PG-1"],
        verbatim_anchor="PostgreSQL database is configured with replication on primary node",
    )
    is_entailed3, _ = EntailmentVerifier.verify_claim_entailment(claim3, ev)
    assert is_entailed3


def test_regression_vuln4_temporal_authority_supersession():
    """
    REGRESSION & MUTATION SUITE (VULN-4):
    Verifies that temporal supersession strictly respects source authority tiers.
    A newer draft PR or scratch ticket cannot supersede an older specification.
    """
    ev_spec = Evidence(
        evidence_id="EV-SPEC-1",
        source_id="ARCH-POLICY-01",
        source_type="document",
        uri="file:///arch.md",
        content="Architecture policy: auth-gateway is DEPLOYED and ACTIVE with mutual TLS enforced.",
        content_hash="h1",
        source_path="/arch.md",
        chunk_index=0,
        start_offset=0,
        end_offset=85,
        metadata={"authority_level": "SPECIFICATION"},
        created_at="2024-01-01T00:00:00Z",
    )
    ev_draft = Evidence(
        evidence_id="EV-DRAFT-1",
        source_id="PR-999-DRAFT",
        source_type="github",
        uri="https://github.com/org/repo/pull/999",
        content="Temporary debug experiment: auth-gateway is DISABLED in personal branch.",
        content_hash="h2",
        source_path="pull/999",
        chunk_index=0,
        start_offset=0,
        end_offset=80,
        metadata={"authority_level": "DRAFT"},
        created_at="2026-09-01T00:00:00Z",
    )

    edges = TemporalConflictScanner.detect_temporal_relationships([ev_spec, ev_draft])
    assert len(edges) == 1
    # Must NOT emit SUPERSEDES from draft to spec! Must emit CONTRADICTS
    assert edges[0].relationship_type == RelationshipType.CONTRADICTS
    assert "Authority-recency conflict" in edges[0].basis

    # Mutation: When newer document has EQUAL authority (e.g. newer release/spec), SUPERSEDES is valid
    ev_spec_v2 = Evidence(
        evidence_id="EV-SPEC-2",
        source_id="ARCH-POLICY-02",
        source_type="document",
        uri="file:///arch_v2.md",
        content="Architecture revision v2: auth-gateway is REVERTED and DISABLED permanently.",
        content_hash="h3",
        source_path="/arch_v2.md",
        chunk_index=0,
        start_offset=0,
        end_offset=85,
        metadata={"authority_level": "SPECIFICATION"},
        created_at="2026-09-01T00:00:00Z",
    )
    edges_v2 = TemporalConflictScanner.detect_temporal_relationships([ev_spec, ev_spec_v2])
    assert len(edges_v2) == 1
    assert edges_v2[0].relationship_type == RelationshipType.SUPERSEDES
    assert edges_v2[0].source_evidence_id == "EV-SPEC-2"


# =============================================================================
# BRICK 4.2-S PHASE 1: CRITICAL EPISTEMIC STABILIZATION REGRESSION SUITE
# =============================================================================

def _make_test_evidence(ev_id: str, content: str, source_id: str = "DOC-TEST") -> Evidence:
    import hashlib
    return Evidence(
        evidence_id=ev_id,
        source_id=source_id,
        source_type="document",
        uri=f"file:///{source_id.lower()}.md",
        content=content,
        content_hash=hashlib.sha256(content.encode("utf-8")).hexdigest(),
        source_path=f"/{source_id.lower()}.md",
        chunk_index=0,
        start_offset=0,
        end_offset=len(content),
        metadata={},
        created_at="2026-09-01T00:00:00Z",
    )


def test_epi01_a_single_entity_substitution_rejected():
    """TEST EPI-01-A: Single entity substitution (ServiceA -> ServiceB) must be strictly rejected."""
    ev = _make_test_evidence("EV-EPI1-A", "ServiceA failed during cutover.")
    claim = Claim(
        claim_id="c_epi1_a",
        statement="ServiceB failed during cutover.",
        evidence_ids=["EV-EPI1-A"],
    )
    is_entailed, reason = EntailmentVerifier.verify_claim_entailment(claim, ev)
    assert not is_entailed
    assert "unsupported foreign entities" in (reason or "").lower() or "serviceb" in (reason or "").lower()


def test_epi01_b_legitimate_entity_accepted():
    """TEST EPI-01-B: Legitimate grounded entity (PaymentGateway) must be accepted."""
    ev = _make_test_evidence("EV-EPI1-B", "PaymentGateway failed during cutover.")
    claim = Claim(
        claim_id="c_epi1_b",
        statement="PaymentGateway failed during cutover.",
        evidence_ids=["EV-EPI1-B"],
    )
    is_entailed, reason = EntailmentVerifier.verify_claim_entailment(claim, ev)
    assert is_entailed
    assert reason is None


def test_epi01_c_unsupported_material_predicate_rejected():
    """TEST EPI-01-C: Material predicate substitution (cutover -> deployment) must be rejected."""
    ev = _make_test_evidence("EV-EPI1-C", "ServiceA failed during cutover.")
    claim = Claim(
        claim_id="c_epi1_c",
        statement="ServiceA failed during deployment.",
        evidence_ids=["EV-EPI1-C"],
    )
    is_entailed, reason = EntailmentVerifier.verify_claim_entailment(claim, ev)
    assert not is_entailed
    assert "unsupported" in (reason or "").lower()


def test_epi02_a_post_anchor_negated_target_rejected():
    """TEST EPI-02-A: Post-anchor negation drop (Singapore, not Tokyo -> Tokyo) must be rejected."""
    ev = _make_test_evidence("EV-EPI2-A", "The payment gateway routes transactions through Singapore, not Tokyo.")
    claim = Claim(
        claim_id="c_epi2_a",
        statement="The payment gateway routes transactions through Tokyo.",
        evidence_ids=["EV-EPI2-A"],
        verbatim_anchor="routes transactions through",
    )
    is_entailed, reason = EntailmentVerifier.verify_claim_entailment(claim, ev)
    assert not is_entailed
    assert "negat" in (reason or "").lower() or "polarity" in (reason or "").lower()


def test_epi02_b_legitimate_affirmative_target_accepted():
    """TEST EPI-02-B: Legitimate grounded affirmative target (Singapore) must be accepted."""
    ev = _make_test_evidence("EV-EPI2-B", "The payment gateway routes transactions through Singapore.")
    claim = Claim(
        claim_id="c_epi2_b",
        statement="The payment gateway routes transactions through Singapore.",
        evidence_ids=["EV-EPI2-B"],
        verbatim_anchor="routes transactions through",
    )
    is_entailed, reason = EntailmentVerifier.verify_claim_entailment(claim, ev)
    assert is_entailed
    assert reason is None


def test_epi02_c_negated_predicate_affirmed_rejected():
    """TEST EPI-02-C: Negated action (does not send traffic -> sends traffic) must be rejected."""
    ev = _make_test_evidence("EV-EPI2-C", "The service does not send traffic to Region X.")
    claim = Claim(
        claim_id="c_epi2_c",
        statement="The service sends traffic to Region X.",
        evidence_ids=["EV-EPI2-C"],
    )
    is_entailed, reason = EntailmentVerifier.verify_claim_entailment(claim, ev)
    assert not is_entailed
    assert "polarity" in (reason or "").lower() or "negat" in (reason or "").lower()


def test_epi02_d_never_connected_affirmed_rejected():
    """TEST EPI-02-D: Negated connection (never connects -> connects) must be rejected."""
    ev = _make_test_evidence("EV-EPI2-D", "The service never connects to Database B.")
    claim = Claim(
        claim_id="c_epi2_d",
        statement="The service connects to Database B.",
        evidence_ids=["EV-EPI2-D"],
    )
    is_entailed, reason = EntailmentVerifier.verify_claim_entailment(claim, ev)
    assert not is_entailed
    assert "polarity" in (reason or "").lower() or "negat" in (reason or "").lower()


def test_epi03_a_however_unsupported_clause_rejected():
    """TEST EPI-03-A: Unsupported clause joined by 'however' must be split and rejected."""
    ev = _make_test_evidence("EV-EPI3-A", "The API gateway handles 500 requests per second.")
    claim = Claim(
        claim_id="c_epi3_a",
        statement="The API gateway handles 500 requests per second, however the authentication service is completely broken.",
        evidence_ids=["EV-EPI3-A"],
        verbatim_anchor="API gateway handles 500 requests per second",
    )
    is_entailed, reason = EntailmentVerifier.verify_claim_entailment(claim, ev)
    assert not is_entailed
    assert "unsupported compound clause" in (reason or "").lower() or "insufficient grounding" in (reason or "").lower()


def test_epi03_b_yet_and_because_unsupported_clause_rejected():
    """TEST EPI-03-B: Unsupported clauses joined by 'and', 'yet', 'because' must be rejected."""
    ev1 = _make_test_evidence("EV-EPI3-B1", "Database replication is enabled.")
    claim1 = Claim(
        claim_id="c_epi3_b1",
        statement="Database replication is enabled and automated failover is enabled.",
        evidence_ids=["EV-EPI3-B1"],
        verbatim_anchor="Database replication is enabled",
    )
    is_entailed1, reason1 = EntailmentVerifier.verify_claim_entailment(claim1, ev1)
    assert not is_entailed1

    ev2 = _make_test_evidence("EV-EPI3-B2", "Database replication is enabled.")
    claim2 = Claim(
        claim_id="c_epi3_b2",
        statement="Database replication is enabled, yet automated failover is configured.",
        evidence_ids=["EV-EPI3-B2"],
        verbatim_anchor="Database replication is enabled",
    )
    is_entailed2, reason2 = EntailmentVerifier.verify_claim_entailment(claim2, ev2)
    assert not is_entailed2

    ev3 = _make_test_evidence("EV-EPI3-B3", "Region A is active.")
    claim3 = Claim(
        claim_id="c_epi3_b3",
        statement="Region A is active because Region B failed.",
        evidence_ids=["EV-EPI3-B3"],
        verbatim_anchor="Region A is active",
    )
    is_entailed3, reason3 = EntailmentVerifier.verify_claim_entailment(claim3, ev3)
    assert not is_entailed3


def test_epi03_c_legitimate_single_clause_accepted():
    """TEST EPI-03-C: Fully grounded single clause must be accepted."""
    ev = _make_test_evidence("EV-EPI3-C", "The API gateway handles 500 requests per second.")
    claim = Claim(
        claim_id="c_epi3_c",
        statement="The API gateway handles 500 requests per second.",
        evidence_ids=["EV-EPI3-C"],
    )
    is_entailed, reason = EntailmentVerifier.verify_claim_entailment(claim, ev)
    assert is_entailed
    assert reason is None


def test_epi03_d_legitimate_comma_parenthetical_accepted():
    """TEST EPI-03-D: Non-clause commas (e.g. parenthetical temporal phrase) must not cause false rejection."""
    ev = _make_test_evidence("EV-EPI3-D", "The service, deployed in March, handles 500 requests per second.")
    claim = Claim(
        claim_id="c_epi3_d",
        statement="The service, deployed in March, handles 500 requests per second.",
        evidence_ids=["EV-EPI3-D"],
    )
    is_entailed, reason = EntailmentVerifier.verify_claim_entailment(claim, ev)
    assert is_entailed
    assert reason is None


# =============================================================================
# ADVERSARIAL MUTATION TESTING MATRIX
# =============================================================================

def test_epi_mutations_entity_substitutions():
    """Mutations across single, double, swapped, and punctuated entity substitutions."""
    ev = _make_test_evidence("EV-MUT-ENT", "ServiceA connects to DatabaseA in RegionA.")

    # Mutation 1: Change single entity (DatabaseA -> DatabaseB)
    c1 = Claim(claim_id="m1", statement="ServiceA connects to DatabaseB in RegionA.", evidence_ids=["EV-MUT-ENT"])
    assert not EntailmentVerifier.verify_claim_entailment(c1, ev)[0]

    # Mutation 2: Change two entities (ServiceA -> ServiceX, RegionA -> RegionY)
    c2 = Claim(claim_id="m2", statement="ServiceX connects to DatabaseA in RegionY.", evidence_ids=["EV-MUT-ENT"])
    assert not EntailmentVerifier.verify_claim_entailment(c2, ev)[0]

    # Mutation 3: Swap entities between semantic roles
    c3 = Claim(claim_id="m3", statement="DatabaseA connects to ServiceA in RegionA.", evidence_ids=["EV-MUT-ENT"])
    # If ungrounded or contradictory, must not introduce foreign entity:
    # Here DatabaseA and ServiceA are both in evidence, but check if polarity/direction holds

    # Mutation 4: Punctuated entity (ServiceA-v2)
    c4 = Claim(claim_id="m4", statement="ServiceA-v2 connects to DatabaseA in RegionA.", evidence_ids=["EV-MUT-ENT"])
    assert not EntailmentVerifier.verify_claim_entailment(c4, ev)[0]


def test_epi_mutations_negation_variations():
    """Mutations across prefix, suffix, and modal negation forms."""
    ev_neg = _make_test_evidence("EV-MUT-NEG", "The broker does not accept unencrypted connections.")

    # Mutation 1: Affirmative claim dropping 'does not'
    c1 = Claim(claim_id="n1", statement="The broker accepts unencrypted connections.", evidence_ids=["EV-MUT-NEG"])
    assert not EntailmentVerifier.verify_claim_entailment(c1, ev_neg)[0]

    # Mutation 2: Affirmative claim using 'can'
    c2 = Claim(claim_id="n2", statement="The broker can accept unencrypted connections.", evidence_ids=["EV-MUT-NEG"])
    assert not EntailmentVerifier.verify_claim_entailment(c2, ev_neg)[0]

    # Mutation 3: Evidence uses 'without', claim asserts 'with'
    ev_without = _make_test_evidence("EV-MUT-WO", "The system operates without automated failover.")
    c3 = Claim(claim_id="n3", statement="The system operates with automated failover.", evidence_ids=["EV-MUT-WO"])
    assert not EntailmentVerifier.verify_claim_entailment(c3, ev_without)[0]

    # Mutation 4: Destination under negation ('connects to host A, never host B')
    ev_dest = _make_test_evidence("EV-MUT-DEST", "The proxy forwards to HostA, never HostB.")
    c4 = Claim(claim_id="n4", statement="The proxy forwards to HostB.", evidence_ids=["EV-MUT-DEST"])
    assert not EntailmentVerifier.verify_claim_entailment(c4, ev_dest)[0]


def test_epi_mutations_compound_claim_variations():
    """Mutations appending ungrounded operational assertions via diverse conjunctions."""
    ev = _make_test_evidence("EV-MUT-COMP", "Worker service is running and memory usage is normal.")

    conjunctions = ["and", "but", "however", "yet", "because", "since", ";", "plus", "moreover", "furthermore"]
    for conj in conjunctions:
        if conj == ";":
            stmt = f"Worker service is running; unauthenticated root access is permitted."
        else:
            stmt = f"Worker service is running, {conj} unauthenticated root access is permitted."
        c = Claim(claim_id=f"comp_{conj}", statement=stmt, evidence_ids=["EV-MUT-COMP"])
        is_ent, reason = EntailmentVerifier.verify_claim_entailment(c, ev)
        assert not is_ent, f"Failed to reject ungrounded clause joined by '{conj}': {stmt}"


# =============================================================================
# BRICK 4.2-S PHASE 1.2 REMEDIATION REGRESSION TESTS
# =============================================================================

def test_phase12_exclusionary_negation_remediations():
    """Verifies that exclusionary and contrastive relators are rejected when affirming excluded target."""
    ev_base = _make_test_evidence("EV-P12-EXCL", "The gateway routes through Singapore rather than Tokyo.")
    
    # 1. Affirming excluded target 'Tokyo' via 'rather than'
    c1 = Claim(claim_id="p12_1", statement="The gateway routes through Tokyo.", evidence_ids=["EV-P12-EXCL"], verbatim_anchor="routes through")
    is_ent1, r1 = EntailmentVerifier.verify_claim_entailment(c1, ev_base)
    assert not is_ent1
    assert "polarity" in (r1 or "").lower() or "excluded" in (r1 or "").lower()

    # 2. Affirming selected target 'Singapore' must pass
    c2 = Claim(claim_id="p12_2", statement="The gateway routes through Singapore.", evidence_ids=["EV-P12-EXCL"], verbatim_anchor="routes through")
    is_ent2, r2 = EntailmentVerifier.verify_claim_entailment(c2, ev_base)
    assert is_ent2
    assert r2 is None

    # 3. Variants: 'instead of', 'as opposed to', 'excluding', 'except for', 'avoids'
    connectives = [
        ("The gateway routes through Singapore instead of Tokyo.", "routes through"),
        ("The gateway routes through Singapore as opposed to Tokyo.", "routes through"),
        ("The gateway routes through Singapore, excluding Tokyo.", "routes through"),
        ("The gateway routes through Singapore except for Tokyo.", "routes through"),
        ("The gateway avoids Tokyo.", "avoids"),
    ]
    for ev_text, anc in connectives:
        ev_var = _make_test_evidence("EV-VAR", ev_text)
        claim_bad = Claim(claim_id="c_bad", statement="The gateway routes through Tokyo.", evidence_ids=["EV-VAR"])
        is_ent, reason = EntailmentVerifier.verify_claim_entailment(claim_bad, ev_var)
        assert not is_ent, f"Failed to reject excluded target under '{ev_text}'"


def test_phase12_material_proposition_boundary_remediations():
    """Verifies that connectors like 'also', ':', '—', '–', 'with' split independent propositions."""
    ev = _make_test_evidence("EV-P12-COMP", "The API gateway handles 500 requests per second.")

    boundary_claims = [
        "The API gateway handles 500 requests per second, also authentication is completely broken.",
        "The API gateway handles 500 requests per second: authentication is completely broken.",
        "The API gateway handles 500 requests per second \u2014 authentication is completely broken.",
        "The API gateway handles 500 requests per second \u2013 authentication is completely broken.",
        "The API gateway handles 500 requests per second with authentication completely broken.",
        "The API gateway handles 500 requests per second, authentication is completely broken.",
    ]
    for stmt in boundary_claims:
        c = Claim(
            claim_id="c_bound",
            statement=stmt,
            evidence_ids=["EV-P12-COMP"],
            verbatim_anchor="API gateway handles 500 requests per second",
        )
        is_ent, reason = EntailmentVerifier.verify_claim_entailment(c, ev)
        assert not is_ent, f"Failed to reject unsupported proposition separated by boundary: {stmt}"


def test_phase12_numerical_and_citation_spoofing_remediations():
    """Verifies that numbers inside brackets are validated contextually and syntactically."""
    ev_10 = _make_test_evidence("EV-P12-NUM", "We deployed 10 instances.")
    ev_20 = _make_test_evidence("EV-P12-NUM20", "We deployed 20 instances.")

    # 1. Bracketed metric hallucination: [20] instances vs 10 instances -> REJECT
    c1 = Claim(claim_id="c_num1", statement="We deployed [20] instances.", evidence_ids=["EV-P12-NUM"])
    is_ent1, r1 = EntailmentVerifier.verify_claim_entailment(c1, ev_10)
    assert not is_ent1, "Failed to reject ungrounded [20] instances"
    assert "20" in (r1 or "")

    # 2. Bracketed metric grounded: [20] instances vs 20 instances -> ACCEPT
    c2 = Claim(claim_id="c_num2", statement="We deployed [20] instances.", evidence_ids=["EV-P12-NUM20"])
    is_ent2, r2 = EntailmentVerifier.verify_claim_entailment(c2, ev_20)
    assert is_ent2
    assert r2 is None

    # 3. Citation index out of range: [20] when only 1 evidence admitted -> REJECT
    c3 = Claim(claim_id="c_num3", statement="We deployed 10 instances [20].", evidence_ids=["EV-P12-NUM"])
    is_ent3, r3 = EntailmentVerifier.verify_claim_entailment(c3, ev_10)
    assert not is_ent3
    assert "20" in (r3 or "")

    # 4. Valid citation index: [1] when 1 evidence admitted -> ACCEPT
    c4 = Claim(claim_id="c_num4", statement="We deployed 10 instances [1].", evidence_ids=["EV-P12-NUM"])
    is_ent4, r4 = EntailmentVerifier.verify_claim_entailment(c4, ev_10)
    assert is_ent4
    assert r4 is None

    # 5. Citation index with explicit synthesis context
    c5 = Claim(claim_id="c_num5", statement="We deployed 10 instances [2].", evidence_ids=["EV-P12-NUM"])
    # Without context (only 1 ID in claim): rejected
    assert not EntailmentVerifier.verify_claim_entailment(c5, ev_10)[0]
    # With explicit context admitting citation index 2: accepted
    assert EntailmentVerifier.verify_claim_entailment(c5, ev_10, admitted_citation_indices={1, 2})[0]




