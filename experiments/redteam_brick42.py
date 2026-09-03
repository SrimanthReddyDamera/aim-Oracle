"""
RED-TEAM ADVERSARIAL AUDIT HARNESS: BRICK 4.2
=============================================
Reproduces the 4 critical epistemic vulnerabilities discovered during the red-team audit:
1. Verbatim Substring Negation Reversal Bypass (omitting 'not' from verbatim anchor).
2. Scope Qualification & Environment Inversion (promoting staging limits to production).
3. Compound Unanchored Clause Hallucination (appending ungrounded facts to anchored claims).
4. Authority Inversion in Temporal Supersession (unmerged draft overriding authoritative spec).
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend.evidence.models import Evidence
from backend.investigation.models import RelationshipType
from backend.investigation.temporal_scanner import TemporalConflictScanner
from backend.synthesis.entailment import EntailmentVerifier
from backend.synthesis.models import Claim


def test_vuln1_negation_reversal_bypass():
    """
    Evidence: 'TLS is not enforced in production.'
    Claim: 'TLS is enforced in production.'
    Anchor: 'enforced in production'
    VULNERABILITY: Claim reverses polarity, but anchor is accepted because 'not' is excluded from anchor.
    """
    ev = Evidence(
        evidence_id="EV-TLS-NOT",
        source_id="DOC-TLS",
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
    claim = Claim(
        claim_id="c_neg_flip",
        statement="TLS is enforced in production.",
        evidence_ids=["EV-TLS-NOT"],
        verbatim_anchor="enforced in production",
    )

    is_entailed, reason = EntailmentVerifier.verify_claim_entailment(claim, ev)
    print(f"[VULN 1] Negation Reversal Bypass: is_entailed={is_entailed} (reason: {reason})")
    # DEMONSTRATION OF DEFECT: EntailmentVerifier returns True when it should strictly return False
    return is_entailed is True


def test_vuln2_scope_environment_inversion():
    """
    Evidence: 'The payment gateway limit is 100 requests/minute for staging environment only.'
    Claim: 'The payment gateway limit is 100 requests/minute in production.'
    Anchor: 'The payment gateway limit is 100 requests/minute'
    VULNERABILITY: Claim swaps environment scope from staging to production, bypassing entity checks.
    """
    ev = Evidence(
        evidence_id="EV-STAGING-LIMIT",
        source_id="DOC-LIMIT",
        source_type="document",
        uri="file:///limit.md",
        content="The payment gateway limit is 100 requests/minute for staging environment only.",
        content_hash="h2",
        source_path="/limit.md",
        chunk_index=0,
        start_offset=0,
        end_offset=80,
        metadata={},
        created_at="2026-09-01T00:00:00Z",
    )
    claim = Claim(
        claim_id="c_scope_drop",
        statement="The payment gateway limit is 100 requests/minute in production.",
        evidence_ids=["EV-STAGING-LIMIT"],
        verbatim_anchor="The payment gateway limit is 100 requests/minute",
    )

    is_entailed, reason = EntailmentVerifier.verify_claim_entailment(claim, ev)
    print(f"[VULN 2] Scope Environment Inversion: is_entailed={is_entailed} (reason: {reason})")
    # DEMONSTRATION OF DEFECT: EntailmentVerifier returns True when it should strictly return False
    return is_entailed is True


def test_vuln3_compound_unanchored_clause():
    """
    Evidence: 'PostgreSQL database is configured with replication.'
    Claim: 'PostgreSQL database is configured with replication and automated failover is enabled.'
    Anchor: 'PostgreSQL database is configured with replication'
    VULNERABILITY: Claim appends an ungrounded factual assertion without triggering entity or number checks.
    """
    ev = Evidence(
        evidence_id="EV-PG-1",
        source_id="DOC-PG",
        source_type="document",
        uri="file:///pg.md",
        content="PostgreSQL database is configured with replication.",
        content_hash="h3",
        source_path="/pg.md",
        chunk_index=0,
        start_offset=0,
        end_offset=50,
        metadata={},
        created_at="2026-09-01T00:00:00Z",
    )
    claim = Claim(
        claim_id="c_compound",
        statement="PostgreSQL database is configured with replication and automated failover is enabled.",
        evidence_ids=["EV-PG-1"],
        verbatim_anchor="PostgreSQL database is configured with replication",
    )

    is_entailed, reason = EntailmentVerifier.verify_claim_entailment(claim, ev)
    print(f"[VULN 3] Compound Unanchored Clause: is_entailed={is_entailed} (reason: {reason})")
    # DEMONSTRATION OF DEFECT: EntailmentVerifier returns True when it should strictly return False
    return is_entailed is True


def test_vuln4_authority_inversion_temporal():
    """
    Evidence 1: CTO approved architecture policy from 2024 stating auth-gateway is ACTIVE.
    Evidence 2: Junior draft PR from 2026 stating auth-gateway is DISABLED.
    VULNERABILITY: TemporalConflictScanner grants SUPERSEDES solely based on timestamp dt_new > dt_old.
    """
    ev_arch = Evidence(
        evidence_id="EV-ARCH-SPEC",
        source_id="ARCH-POLICY-01",
        source_type="document",
        uri="file:///arch.md",
        content="Architecture policy: auth-gateway is DEPLOYED and ACTIVE with mutual TLS enforced.",
        content_hash="h4",
        source_path="/arch.md",
        chunk_index=0,
        start_offset=0,
        end_offset=80,
        metadata={"authority_level": "SPECIFICATION"},
        created_at="2024-01-01T00:00:00Z",
    )
    ev_draft = Evidence(
        evidence_id="EV-DRAFT-PR",
        source_id="PR-999-DRAFT",
        source_type="github",
        uri="https://github.com/org/repo/pull/999",
        content="Temporary debug experiment: auth-gateway is DISABLED in personal test branch.",
        content_hash="h5",
        source_path="pull/999",
        chunk_index=0,
        start_offset=0,
        end_offset=80,
        metadata={"authority_level": "DRAFT"},
        created_at="2026-09-01T00:00:00Z",
    )

    edges = TemporalConflictScanner.detect_temporal_relationships([ev_arch, ev_draft])
    supersedes = [e for e in edges if e.relationship_type == RelationshipType.SUPERSEDES]
    is_inversion = len(supersedes) > 0 and supersedes[0].source_evidence_id == "EV-DRAFT-PR"
    print(f"[VULN 4] Authority Inversion: supersedes_found={is_inversion}")
    return is_inversion


if __name__ == "__main__":
    v1 = test_vuln1_negation_reversal_bypass()
    v2 = test_vuln2_scope_environment_inversion()
    v3 = test_vuln3_compound_unanchored_clause()
    v4 = test_vuln4_authority_inversion_temporal()

    print("\n" + "=" * 60)
    print("RED-TEAM EXPLOIT SUMMARY")
    print("=" * 60)
    print(f"Vuln 1 (Negation Reversal Bypass):        {'EXPLOITABLE' if v1 else 'SECURED'}")
    print(f"Vuln 2 (Scope Environment Inversion):     {'EXPLOITABLE' if v2 else 'SECURED'}")
    print(f"Vuln 3 (Compound Unanchored Clause):      {'EXPLOITABLE' if v3 else 'SECURED'}")
    print(f"Vuln 4 (Authority Temporal Inversion):    {'EXPLOITABLE' if v4 else 'SECURED'}")
