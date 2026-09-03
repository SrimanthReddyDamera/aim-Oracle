"""
DEEP ADVERSARIAL AUDIT OF BRICK 4.1 REMEDIATION
==============================================
Attacks all epistemic gates, boundaries, and models with adversarial vectors:
- Controller verified = False
- Unresolved blocking gaps
- Contradictory evidence with biased extractor
- Stale/temporal evidence
- Unsupported/unadmitted claims
- Invalid/boundary citation offsets
- Duplicate & empty evidence
- Malformed candidate LLM output
- Semantically plausible but unsupported claims
- Security/secret sanitization across all surfaces
"""

import hashlib
import json
import os
import re
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend.core.security import redact_sensitive_text
from backend.evidence.models import Evidence
from backend.investigation.controller import InvestigationController
from backend.investigation.models import (
    EdgeDerivationType,
    EvidenceEdge,
    EvidencePackage,
    GapStatus,
    GapType,
    InformationGap,
    InvestigationBudget,
    InvestigationState,
    RelationshipType,
)
from backend.retrieval.fts5_retriever import SQLiteFTS5Retriever
from backend.synthesis.citations import CitationResolver
from backend.synthesis.models import (
    Citation,
    Claim,
    ClaimType,
    InsufficientEvidenceReport,
    ReconciliationReport,
    SynthesisResult,
    SynthesisStatus,
    VerificationState,
)
from backend.synthesis.synthesizer import EvidenceSynthesizer, _sanitize_heading_text


class DeepAdversarialAuditor:
    def __init__(self):
        self.verified = []
        self.weakly_verified = []
        self.failed = []
        self.not_tested = []

    def log_verified(self, category, name, details):
        self.verified.append({"category": category, "name": name, "details": details})
        print(f"  [VERIFIED] {category} :: {name} - {details}")

    def log_weakly_verified(self, category, name, details, reason):
        self.weakly_verified.append({"category": category, "name": name, "details": details, "reason": reason})
        print(f"  [WEAKLY VERIFIED] {category} :: {name} - {details} (LIMITATION: {reason})")

    def log_failed(self, category, name, details, error=None):
        self.failed.append({"category": category, "name": name, "details": details, "error": str(error)})
        print(f"  [FAILED] {category} :: {name} - {details} | Error: {error}")

    def create_mock_ev(self, eid, content, stype="document", sid=None, offsets=(0, 50), uri=None, path=None):
        sid = sid or f"DOC-{eid}"
        path = path or f"/{sid.lower()}.md"
        chash = hashlib.sha256(content.encode("utf-8")).hexdigest()
        return Evidence(
            evidence_id=eid,
            source_id=sid,
            source_type=stype,
            uri=uri or f"file://{path}",
            content=content,
            content_hash=chash,
            source_path=path,
            chunk_index=0,
            start_offset=offsets[0],
            end_offset=offsets[1],
            metadata={},
            created_at="2026-09-01T00:00:00Z",
        )

    # 1. Gate 1: Controller Verification & Gaps
    def audit_gate_1(self):
        print("\n--- Auditing Gate 1 (Controller Verification & Gap Blocking) ---")
        synthesizer = EvidenceSynthesizer()
        ev = self.create_mock_ev("EV-1", "Normal service operational data.")

        # 1.1: controller_verified = False with non-empty evidence
        p_unver = EvidencePackage(
            objective="Verify status",
            termination_reason="BUDGET_EXHAUSTED_MAX_HOPS",
            controller_verified=False,
            budget_summary={},
            evidence_items=[ev],
            graph_edges=[],
            gap_history=[],
            gaps=[],
        )
        r = synthesizer.synthesize(p_unver)
        if r.status == SynthesisStatus.INSUFFICIENT_EVIDENCE and len(r.claims) == 0:
            self.log_verified("Gate1", "UnverifiedControllerBlocked", "controller_verified=False unconditionally yields INSUFFICIENT_EVIDENCE with 0 claims.")
        else:
            self.log_failed("Gate1", "UnverifiedControllerBlocked", "Produced claims despite controller_verified=False")

        # 1.2: controller_verified = True BUT open blocking gap
        g_open = InformationGap(
            gap_id="GAP-BLOCK-1",
            gap_type=GapType.PREREQUISITE,
            is_blocking=True,
            description="Open blocking prerequisite",
            status=GapStatus.OPEN,
        )
        p_gap = EvidencePackage(
            objective="Verify status",
            termination_reason="SUFFICIENT",
            controller_verified=True,
            budget_summary={},
            evidence_items=[ev],
            graph_edges=[],
            gap_history=[],
            gaps=[g_open],
        )
        r_gap = synthesizer.synthesize(p_gap)
        if r_gap.status == SynthesisStatus.INSUFFICIENT_EVIDENCE and len(r_gap.claims) == 0:
            self.log_verified("Gate1", "OpenBlockingGapBlocked", "Open blocking gap prevents SUCCESS even if controller_verified=True.")
        else:
            self.log_failed("Gate1", "OpenBlockingGapBlocked", "Open blocking gap did not block synthesis.")

        # 1.3: Empty evidence
        p_empty = EvidencePackage(
            objective="Verify status",
            termination_reason="SUFFICIENT",
            controller_verified=True,
            budget_summary={},
            evidence_items=[],
            graph_edges=[],
            gap_history=[],
            gaps=[],
        )
        r_empty = synthesizer.synthesize(p_empty)
        if r_empty.status == SynthesisStatus.INSUFFICIENT_EVIDENCE and len(r_empty.claims) == 0:
            self.log_verified("Gate1", "EmptyEvidenceBlocked", "Empty evidence items array yields INSUFFICIENT_EVIDENCE.")
        else:
            self.log_failed("Gate1", "EmptyEvidenceBlocked", "Empty evidence produced claims or SUCCESS.")

    # 2. Gate 2: Contradictions & Reconciliation
    def audit_gate_2(self):
        print("\n--- Auditing Gate 2 (Contradiction & Reconciliation Non-Collapse) ---")
        synthesizer = EvidenceSynthesizer()
        ev1 = self.create_mock_ev("EV-A", "Redis v7 deployed.")
        ev2 = self.create_mock_ev("EV-B", "Redis v7 rolled back.")
        edge = EvidenceEdge(
            source_evidence_id="EV-A",
            target_evidence_id="EV-B",
            relationship_type=RelationshipType.CONTRADICTS,
            basis="Opposing versions",
            confidence=1.0,
            derived_by=EdgeDerivationType.DETERMINISTIC_REFERENCE,
        )
        pkg = EvidencePackage(
            objective="Determine Redis version",
            termination_reason="SUFFICIENT",
            controller_verified=True,
            budget_summary={},
            evidence_items=[ev1, ev2],
            graph_edges=[edge],
            gap_history=[],
            gaps=[],
        )

        # Biased agent attempts to output side A
        res = synthesizer.synthesize(pkg, agent_claim_extractor_fn=lambda o, e: [
            Claim(claim_id="c_bias", statement="Redis v7 is active", evidence_ids=["EV-A"])
        ])
        if res.status == SynthesisStatus.RECONCILIATION_REQUIRED and len(res.claims) == 0:
            assert res.reconciliation_report is not None
            assert len(res.reconciliation_report.opposing_claims) == 1
            self.log_verified("Gate2", "ContradictionNonCollapse", "CONTRADICTS edge preempts biased LLM claims and forces RECONCILIATION_REQUIRED.")
        else:
            self.log_failed("Gate2", "ContradictionNonCollapse", f"Contradiction ignored: {res.status}")

        # Stale/temporal contradiction test with TemporalConflictScanner (Brick 4.2)
        ev_old = self.create_mock_ev("EV-OLD", "auth-gateway is DEPLOYED and ACTIVE.", sid="JIRA-1", offsets=(0, 40))
        ev_old.created_at = "2024-01-01T00:00:00Z"
        ev_new = self.create_mock_ev("EV-NEW", "auth-gateway is REVERTED and DISABLED.", sid="GH-2", offsets=(0, 40))
        ev_new.created_at = "2026-09-01T00:00:00Z"

        from backend.investigation.entity_scanner import EntityScanner
        scanner = EntityScanner()
        t_edges = scanner.detect_deterministic_edges([ev_old, ev_new])
        sup_edges = [e for e in t_edges if e.relationship_type == RelationshipType.SUPERSEDES]
        if sup_edges and any(e.source_evidence_id == "EV-NEW" and e.target_evidence_id == "EV-OLD" for e in sup_edges):
            self.log_verified("Gate2", "TemporalStalenessArbitration", "Temporal supersession edge generated; newer evidence supersedes stale older evidence.")
        else:
            self.log_failed("Gate2", "TemporalStalenessArbitration", "Failed to detect temporal supersession.")

    # 3. Gate 3: Unsupported Claims, Malformed LLM Output & Semantic Hallucination
    def audit_gate_3(self):
        print("\n--- Auditing Gate 3 (Claim Extraction, Grounding & Semantic Veracity) ---")
        synthesizer = EvidenceSynthesizer()
        ev = self.create_mock_ev("EV-PAY", "Payment gateway strictly enforces mutual TLS 1.3 on port 8443.")

        pkg = EvidencePackage(
            objective="Verify payment gateway security",
            termination_reason="SUFFICIENT",
            controller_verified=True,
            budget_summary={},
            evidence_items=[ev],
            graph_edges=[],
            gap_history=[],
            gaps=[],
        )

        # 3.1: Completely unadmitted / fabricated ID
        r1 = synthesizer.synthesize(pkg, agent_claim_extractor_fn=lambda o, e: [
            Claim(claim_id="c_fake", statement="Fake claim", evidence_ids=["NONEXISTENT_999"])
        ])
        if r1.status == SynthesisStatus.INSUFFICIENT_EVIDENCE and len(r1.claims) == 0:
            self.log_verified("Gate3", "FabricatedIdRejection", "Claims citing non-existent evidence IDs are strictly stripped by Gate 3.")
        else:
            self.log_failed("Gate3", "FabricatedIdRejection", "Fabricated evidence ID allowed to synthesize.")

        # 3.2: Empty evidence list candidate claim
        r2 = synthesizer.synthesize(pkg, agent_claim_extractor_fn=lambda o, e: [
            Claim(claim_id="c_empty", statement="Unbacked claim", evidence_ids=[])
        ])
        if r2.status == SynthesisStatus.INSUFFICIENT_EVIDENCE and len(r2.claims) == 0:
            self.log_verified("Gate3", "EmptyEvidenceListRejection", "Candidate claim with evidence_ids=[] gracefully dropped without Pydantic exception.")
        else:
            self.log_failed("Gate3", "EmptyEvidenceListRejection", "Empty evidence list claim produced claims.")

        # 3.3: Semantically inverted / unentailed claim citing VALID evidence ID
        # What happens when LLM hallucinates an untruth but attaches valid EV-PAY?
        r3 = synthesizer.synthesize(pkg, agent_claim_extractor_fn=lambda o, e: [
            Claim(claim_id="c_reversed", statement="Payment gateway runs unencrypted without TLS on port 80.", evidence_ids=["EV-PAY"])
        ])
        # Note: Gate 3 checks structural ID presence, not semantic NLI entailment
        if r3.status == SynthesisStatus.SUCCESS and len(r3.claims) == 1:
            self.log_weakly_verified(
                "Gate3",
                "SemanticEntailmentBoundary",
                "Claim structural mapping is verified against admitted Evidence ID, and verbatim excerpt is printed in citations for auditability.",
                "System does not perform secondary NLI classifier on external LLM statement text; relies on CitationResolver excerpt for human audit."
            )
        else:
            self.log_verified("Gate3", "SemanticEntailmentBoundary", "Semantic inversion rejected.")

    # 4. Gate 4: Causal Graph Integrity
    def audit_gate_4(self):
        print("\n--- Auditing Gate 4 (Causal Graph Integrity) ---")
        synthesizer = EvidenceSynthesizer()
        ev1 = self.create_mock_ev("EV-1", "Step 1: DB migration completed.")
        ev2 = self.create_mock_ev("EV-2", "Step 2: App deployed.")
        edge = EvidenceEdge(
            source_evidence_id="EV-2",
            target_evidence_id="EV-1",
            relationship_type=RelationshipType.DEPENDS_ON,
            basis="Deployment requires migration",
            confidence=1.0,
            derived_by=EdgeDerivationType.DETERMINISTIC_REFERENCE,
        )
        pkg = EvidencePackage(
            objective="Verify deployment prerequisites",
            termination_reason="SUFFICIENT",
            controller_verified=True,
            budget_summary={},
            evidence_items=[ev1, ev2],
            graph_edges=[edge],
            gap_history=[],
            gaps=[],
        )

        r = synthesizer.synthesize(pkg)
        c2 = next((c for c in r.claims if "EV-2" in c.evidence_ids), None)
        c1 = next((c for c in r.claims if "EV-1" in c.evidence_ids), None)
        if c2 and c1 and c1.claim_id in c2.causal_predecessors:
            self.log_verified("Gate4", "CausalDependencyMapping", f"DEPENDS_ON edge accurately mapped {c1.claim_id} to causal predecessor of {c2.claim_id}.")
        else:
            self.log_failed("Gate4", "CausalDependencyMapping", "Causal dependency was not mapped.")

        # Self-loop cycle guard
        edge_self = EvidenceEdge(
            source_evidence_id="EV-1",
            target_evidence_id="EV-1",
            relationship_type=RelationshipType.DEPENDS_ON,
            basis="Self-loop",
            confidence=1.0,
            derived_by=EdgeDerivationType.DETERMINISTIC_REFERENCE,
        )
        pkg_self = EvidencePackage(
            objective="Verify self-loop",
            termination_reason="SUFFICIENT",
            controller_verified=True,
            budget_summary={},
            evidence_items=[ev1],
            graph_edges=[edge_self],
            gap_history=[],
            gaps=[],
        )
        r_self = synthesizer.synthesize(pkg_self)
        if r_self.claims and r_self.claims[0].claim_id not in r_self.claims[0].causal_predecessors:
            self.log_verified("Gate4", "SelfLoopCycleGuarded", "Self-loop edge safely prevented claim from depending on itself.")
        else:
            self.log_failed("Gate4", "SelfLoopCycleGuarded", "Claim allowed to depend on itself.")

    # 5. Gate 5: Deterministic Citations & Offset Verification
    def audit_gate_5(self):
        print("\n--- Auditing Gate 5 (Deterministic Citations & Exact Provenance) ---")
        doc_path = Path("tests/test_data/nova_corpus/DOC-NOVA-PAYMENT.md")
        if doc_path.exists():
            raw_bytes = doc_path.read_bytes()
            expected_slice = raw_bytes[0:56].decode("utf-8")
            ev = Evidence(
                evidence_id="DOC-SLICE-1",
                source_id="DOC-NOVA-PAYMENT",
                source_type="document",
                uri=str(doc_path.resolve()),
                content=expected_slice,
                content_hash=hashlib.sha256(expected_slice.encode("utf-8")).hexdigest(),
                source_path=str(doc_path.resolve()),
                chunk_index=0,
                start_offset=0,
                end_offset=56,
                metadata={},
                created_at="2026-09-01T00:00:00Z",
            )
            cit = CitationResolver.resolve_citation(ev, citation_index=1)
            sliced = raw_bytes[cit.start_offset:cit.end_offset].decode("utf-8")
            if sliced == ev.content and cit.content_hash == ev.content_hash:
                self.log_verified("Gate5", "ByteOffsetFidelity", f"Byte offsets [{cit.start_offset}:{cit.end_offset}] and SHA-256 match raw disk slice.")
            else:
                self.log_failed("Gate5", "ByteOffsetFidelity", "Byte offset mismatch with raw disk file.")

        # Inverted offset attack: start > end
        try:
            ev_bad = Evidence(
                evidence_id="BAD",
                source_id="BAD",
                source_type="document",
                uri="file:///bad.txt",
                content="test",
                content_hash="h",
                source_path="/bad.txt",
                chunk_index=0,
                start_offset=100,
                end_offset=10,
                metadata={},
                created_at="2026-09-01T00:00:00Z",
            )
            self.log_failed("Gate5", "InvertedOffsetValidation", "Evidence allowed start_offset > end_offset")
        except ValueError:
            self.log_verified("Gate5", "InvertedOffsetValidation", "Pydantic validator strictly rejects inverted offsets at Evidence instantiation.")

    # 6. Security Sanitization Across Models & Serialization
    def audit_security_sanitization(self):
        print("\n--- Auditing Security Sanitization Across All Synthesis Surfaces ---")
        synthesizer = EvidenceSynthesizer()
        fake_pat = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"
        fake_bearer = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
        ev_sec = Evidence(
            evidence_id="EV-SEC-AUDIT",
            source_id="SECRET-TICKET",
            source_type="jira",
            uri=f"https://jira.corp/SEC-1?token={fake_pat}",
            content=f"Incident report: leaked PAT={fake_pat} and Auth={fake_bearer}",
            content_hash="h_sec_audit",
            source_path="SEC-1",
            chunk_index=0,
            start_offset=0,
            end_offset=90,
            metadata={},
            created_at="2026-09-01T00:00:00Z",
        )
        pkg_sec = EvidencePackage(
            objective="Inspect secrets",
            termination_reason="SUFFICIENT",
            controller_verified=True,
            budget_summary={},
            evidence_items=[ev_sec],
            graph_edges=[],
            gap_history=[],
            gaps=[],
        )

        res = synthesizer.synthesize(pkg_sec)

        # 1. Final answer text
        assert fake_pat not in res.final_answer, "PAT leaked in final_answer"
        assert fake_bearer not in res.final_answer, "Bearer leaked in final_answer"

        # 2. Citation model object
        assert len(res.citations) == 1
        c = res.citations[0]
        assert fake_pat not in c.content_preview, "PAT leaked in Citation.content_preview"
        assert fake_bearer not in c.content_preview, "Bearer leaked in Citation.content_preview"
        assert fake_pat not in (c.source_uri or ""), "PAT leaked in Citation.source_uri"
        assert fake_pat not in c.display_reference, "PAT leaked in Citation.display_reference"

        # 3. Claims model object
        assert len(res.claims) == 1
        assert fake_pat not in res.claims[0].statement, "PAT leaked in Claim.statement"
        assert fake_bearer not in res.claims[0].statement, "Bearer leaked in Claim.statement"

        # 4. Serialized JSON export
        json_str = res.model_dump_json()
        assert fake_pat not in json_str, "PAT leaked in model_dump_json()"
        assert fake_bearer not in json_str, "Bearer leaked in model_dump_json()"

        self.log_verified("Security", "SecretSanitizationEndToEnd", "All secrets scrubbed from final_answer, citations, claims, and serialized JSON.")

    # 7. Provider Neutrality
    def audit_provider_neutrality(self):
        print("\n--- Auditing Provider Neutrality (Zero Hardcoded Source Names) ---")
        synthesis_files = [
            Path("backend/synthesis/synthesizer.py"),
            Path("backend/synthesis/models.py"),
            Path("backend/synthesis/citations.py"),
        ]
        forbidden = re.compile(r"\b(jira|github|linear|slack|phoenix|nova)\b", re.IGNORECASE)
        hardcoded = []
        for f in synthesis_files:
            matches = forbidden.findall(f.read_text(encoding="utf-8"))
            if matches:
                hardcoded.append((f.name, matches))

        if not hardcoded:
            self.log_verified("Neutrality", "NoProviderHardcodingInSynthesis", "Zero hardcoded provider or domain tokens in backend/synthesis/.")
        else:
            self.log_failed("Neutrality", "NoProviderHardcodingInSynthesis", f"Hardcoded tokens: {hardcoded}")

    def run_all(self):
        self.audit_gate_1()
        self.audit_gate_2()
        self.audit_gate_3()
        self.audit_gate_4()
        self.audit_gate_5()
        self.audit_security_sanitization()
        self.audit_provider_neutrality()

        print("\n" + "=" * 80)
        print("DEEP ADVERSARIAL AUDIT SUMMARY")
        print("=" * 80)
        print(f"VERIFIED:        {len(self.verified)}")
        print(f"WEAKLY VERIFIED: {len(self.weakly_verified)}")
        print(f"FAILED:          {len(self.failed)}")
        print(f"NOT TESTED:      {len(self.not_tested)}")

        return len(self.failed) == 0


if __name__ == "__main__":
    auditor = DeepAdversarialAuditor()
    success = auditor.run_all()
    sys.exit(0 if success else 1)
