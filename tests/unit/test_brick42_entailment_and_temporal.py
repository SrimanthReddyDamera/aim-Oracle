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


