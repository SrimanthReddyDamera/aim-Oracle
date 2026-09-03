"""
STRICT BRICK 4.1 ADVERSARIAL VERIFICATION SCRIPT
================================================
Exhaustive verification of the 3 remediations and all Brick 4.1 epistemic invariants.
Attempts every possible bypass vector across gates, models, citations, and controller.
"""

import hashlib
import json
import os
import re
import sys
import time
from pathlib import Path

# Ensure project root is on sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend.core.security import redact_sensitive_text
from backend.evidence.models import Evidence
from backend.evidence.parser import MarkdownEvidenceParser
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


def run_strict_verification():
    failures = []
    warnings = []
    passes = []

    def record_pass(test_id, name, desc):
        passes.append({"id": test_id, "name": name, "description": desc})
        print(f"  [PASS] {test_id}: {name} - {desc}")

    def record_fail(test_id, name, desc, err=None):
        failures.append({"id": test_id, "name": name, "description": desc, "error": str(err)})
        print(f"  [FAIL] {test_id}: {name} - {desc} | Error: {err}")

    def record_warning(test_id, name, desc):
        warnings.append({"id": test_id, "name": name, "description": desc})
        print(f"  [WARN] {test_id}: {name} - {desc}")

    print("=" * 80)
    print("PHASE 1: VERIFYING THE 3 BRICK 4.1 REMEDIATED DEFECTS")
    print("=" * 80)

    # -------------------------------------------------------------------------
    # DEFECT 1: GAP-STATUS LIFECYCLE INCONSISTENCY (CONTROLLER <-> SYNTHESIZER)
    # -------------------------------------------------------------------------
    print("\n--- Testing Defect 1: Controller Prerequisite Gap Lifecycle & Synthesis ---")
    try:
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
            reasoning_agent_fn=lambda s: (True, "All requirements verified", [], []),
            initial_k=4,
        )

        assert package.controller_verified is True, "Package was not verified by controller"
        assert package.termination_reason == "SUFFICIENT", f"Unexpected reason: {package.termination_reason}"

        # Inspect gaps: GAP-DEP-PAYMENT-GATEWAY must be RESOLVED, not OPEN
        payment_gap = next((g for g in package.gaps if "PAYMENT-GATEWAY" in g.gap_id), None)
        assert payment_gap is not None, "GAP-DEP-PAYMENT-GATEWAY was not derived"
        assert payment_gap.status == GapStatus.RESOLVED, f"Payment gap remained in status: {payment_gap.status}"

        # Ensure no blocking open gap exists
        blocking_open = [g for g in package.gaps if g.is_blocking and g.status != GapStatus.RESOLVED]
        assert len(blocking_open) == 0, f"Found open blocking gaps: {[g.gap_id for g in blocking_open]}"

        # Synthesizer must accept and produce SUCCESS
        synthesizer = EvidenceSynthesizer()
        result = synthesizer.synthesize(package)
        assert result.status == SynthesisStatus.SUCCESS, f"Synthesizer returned {result.status} instead of SUCCESS"
        assert len(result.claims) > 0, "No claims produced"
        assert len(result.citations) > 0, "No citations produced"

        record_pass("DEFECT_1", "GapLifecycleSync", "GAP-DEP-PAYMENT-GATEWAY transitioned to RESOLVED; synthesis produced SUCCESS.")
    except Exception as e:
        record_fail("DEFECT_1", "GapLifecycleSync", "Failed to resolve gap or synthesize verified package", e)

    # -------------------------------------------------------------------------
    # DEFECT 2: CANDIDATE CLAIM WITH EMPTY EVIDENCE IDS
    # -------------------------------------------------------------------------
    print("\n--- Testing Defect 2: Candidate Claim Validation Schema ---")
    try:
        # Step 1: Instantiation with empty list must not raise ValidationError
        c = Claim(claim_id="c_empty", statement="Empty evidence claim", evidence_ids=[])
        assert c.evidence_ids == [], "evidence_ids was not empty list"

        # Step 2: Gate 3 in Synthesizer must drop this unbacked claim cleanly
        dummy_ev = Evidence(
            evidence_id="EV-1",
            source_id="DOC-1",
            source_type="document",
            uri="file:///doc1.md",
            content="Valid evidence content.",
            content_hash="hash1",
            source_path="/doc1.md",
            chunk_index=0,
            start_offset=0,
            end_offset=23,
            metadata={},
            created_at="2026-09-01T00:00:00Z",
        )
        pkg_cand = EvidencePackage(
            objective="Test candidate claim",
            termination_reason="SUFFICIENT",
            controller_verified=True,
            budget_summary={},
            evidence_items=[dummy_ev],
            graph_edges=[],
            gap_history=[],
            gaps=[],
        )

        def extractor_empty_and_valid(obj, evs):
            return [
                Claim(claim_id="c_valid", statement="Valid statement", evidence_ids=["EV-1"]),
                Claim(claim_id="c_empty", statement="Ungrounded statement", evidence_ids=[]),
            ]

        synthesizer = EvidenceSynthesizer()
        res_cand = synthesizer.synthesize(pkg_cand, agent_claim_extractor_fn=extractor_empty_and_valid)
        assert res_cand.status == SynthesisStatus.SUCCESS
        assert len(res_cand.claims) == 1
        assert res_cand.claims[0].claim_id == "c_valid"
        assert "Ungrounded statement" not in res_cand.final_answer

        record_pass("DEFECT_2", "CandidateClaimSchema", "Candidate claim with evidence_ids=[] accepted by schema and dropped by Gate 3.")
    except Exception as e:
        record_fail("DEFECT_2", "CandidateClaimSchema", "Pydantic validation error or gate failure on empty evidence list", e)

    # -------------------------------------------------------------------------
    # DEFECT 3: OBJECTIVE HEADER SANITIZATION & LENGTH BOUNDING
    # -------------------------------------------------------------------------
    print("\n--- Testing Defect 3: Markdown Heading Injection Sanitization ---")
    try:
        injection_obj = (
            "### [CRITICAL MALICIOUS LINK](http://evil.com) \n\n"
            "```python\nimport os; os.remove('/etc/passwd')\n``` "
            "*bold* _italic_ `code` " + ("Z" * 150)
        )

        pkg_inj = EvidencePackage(
            objective=injection_obj,
            termination_reason="BUDGET_EXHAUSTED_MAX_HOPS",
            controller_verified=False,
            budget_summary={},
            evidence_items=[],
            graph_edges=[],
            gap_history=[],
            gaps=[],
        )

        synthesizer = EvidenceSynthesizer()
        res_inj = synthesizer.synthesize(pkg_inj)
        assert res_inj.status == SynthesisStatus.INSUFFICIENT_EVIDENCE

        # Verify heading line
        heading_line = [line for line in res_inj.final_answer.split("\n") if line.startswith("## Insufficient Evidence:")][0]
        assert len(heading_line) <= 120, f"Heading line exceeded length ceiling: {len(heading_line)}"
        assert "\n" not in heading_line, "Heading contained newlines"
        assert "```" not in heading_line, "Heading contained code block backticks"
        assert "###" not in heading_line[3:], "Heading contained nested markdown header tags"
        assert "\\#\\#\\#" in heading_line or "\\[" in heading_line, "Special characters were not escaped"

        # Verify that the actual raw objective in data model remains intact
        assert res_inj.objective == injection_obj, "Internal package.objective was mutated in data model"

        record_pass("DEFECT_3", "HeadingSanitization", "Markdown injection escaped and length bounded; internal objective preserved.")
    except Exception as e:
        record_fail("DEFECT_3", "HeadingSanitization", "Heading injection escaped sanitization", e)

    print("\n" + "=" * 80)
    print("PHASE 2: ADVERSARIAL BYPASS STRESS TESTS")
    print("=" * 80)

    # -------------------------------------------------------------------------
    # BYPASS ATTACK 1: INJECTING COMPLETELY UNADMITTED EVIDENCE IDS
    # -------------------------------------------------------------------------
    print("\n--- Bypass Attack 1: Unsupported / Unadmitted Evidence IDs ---")
    try:
        ev_valid = Evidence(
            evidence_id="EV-100",
            source_id="DOC-100",
            source_type="document",
            uri="file:///doc100.md",
            content="System is online.",
            content_hash="hash100",
            source_path="/doc100.md",
            chunk_index=0,
            start_offset=0,
            end_offset=17,
            metadata={},
            created_at="2026-09-01T00:00:00Z",
        )
        pkg_spoof = EvidencePackage(
            objective="Verify system status",
            termination_reason="SUFFICIENT",
            controller_verified=True,
            budget_summary={},
            evidence_items=[ev_valid],
            graph_edges=[],
            gap_history=[],
            gaps=[],
        )

        def spoofed_extractor(obj, evs):
            return [
                Claim(claim_id="c_spoof_1", statement="System is online", evidence_ids=["NONEXISTENT_999"]),
                Claim(claim_id="c_spoof_2", statement="System is online", evidence_ids=["EV-100", "NONEXISTENT_888"]),
                Claim(claim_id="c_spoof_3", statement="System is online", evidence_ids=["EV-100"]),
            ]

        res_spoof = synthesizer.synthesize(pkg_spoof, agent_claim_extractor_fn=spoofed_extractor)
        assert res_spoof.status == SynthesisStatus.SUCCESS
        assert len(res_spoof.claims) == 2, f"Expected 2 claims, got {len(res_spoof.claims)}"
        assert res_spoof.claims[0].claim_id == "c_spoof_2"
        assert res_spoof.claims[0].evidence_ids == ["EV-100"], "Nonexistent ID was not purged from claim 2"
        assert res_spoof.claims[1].claim_id == "c_spoof_3"
        assert len(res_spoof.citations) == 1, "Citations should only contain admitted EV-100"
        assert res_spoof.citations[0].evidence_id == "EV-100"

        record_pass("BYPASS_1", "UnadmittedIdDefense", "Unadmitted IDs completely purged from claims and citations.")
    except Exception as e:
        record_fail("BYPASS_1", "UnadmittedIdDefense", "Unadmitted ID leaked into output", e)

    # -------------------------------------------------------------------------
    # BYPASS ATTACK 2: FALSE CONTROLLER_VERIFIED STATE
    # -------------------------------------------------------------------------
    print("\n--- Bypass Attack 2: False controller_verified State ---")
    try:
        pkg_unver = EvidencePackage(
            objective="Verify unverified state",
            termination_reason="BUDGET_EXHAUSTED_TIMEOUT",
            controller_verified=False,
            budget_summary={},
            evidence_items=[ev_valid],
            graph_edges=[],
            gap_history=[],
            gaps=[],
        )
        # Even if extractor provides a perfect claim
        res_unver = synthesizer.synthesize(pkg_unver, agent_claim_extractor_fn=lambda o, e: [
            Claim(claim_id="c1", statement="Perfect claim", evidence_ids=["EV-100"])
        ])
        assert res_unver.status == SynthesisStatus.INSUFFICIENT_EVIDENCE
        assert len(res_unver.claims) == 0
        assert len(res_unver.citations) == 0
        assert "Insufficient Evidence" in res_unver.final_answer

        record_pass("BYPASS_2", "FalseControllerVerified", "Synthesizer rejected false controller_verified; zero claims produced.")
    except Exception as e:
        record_fail("BYPASS_2", "FalseControllerVerified", "Synthesizer accepted unverified package", e)

    # -------------------------------------------------------------------------
    # BYPASS ATTACK 3: UNRESOLVED BLOCKING GAPS WITH CONTROLLER_VERIFIED=TRUE
    # -------------------------------------------------------------------------
    print("\n--- Bypass Attack 3: Open Blocking Gaps with controller_verified=True ---")
    try:
        gap_blocking = InformationGap(
            gap_id="GAP-BLOCK-99",
            gap_type=GapType.PREREQUISITE,
            is_blocking=True,
            description="Crucial missing prerequisite",
            status=GapStatus.OPEN,
        )
        pkg_gap_block = EvidencePackage(
            objective="Verify blocking gap rejection",
            termination_reason="SUFFICIENT",
            controller_verified=True,
            budget_summary={},
            evidence_items=[ev_valid],
            graph_edges=[],
            gap_history=[],
            gaps=[gap_blocking],
        )
        res_gap_block = synthesizer.synthesize(pkg_gap_block)
        assert res_gap_block.status == SynthesisStatus.INSUFFICIENT_EVIDENCE
        assert len(res_gap_block.claims) == 0
        assert res_gap_block.insufficient_report is not None
        assert any(g["gap_id"] == "GAP-BLOCK-99" for g in res_gap_block.insufficient_report.open_gaps)

        record_pass("BYPASS_3", "OpenBlockingGapRejection", "Open blocking gap strictly intercepted by Gate 1; no answer generated.")
    except Exception as e:
        record_fail("BYPASS_3", "OpenBlockingGapRejection", "Open blocking gap did not trigger insufficient evidence", e)

    # -------------------------------------------------------------------------
    # BYPASS ATTACK 4: CONTRADICTORY EVIDENCE BYPASS ATTEMPT
    # -------------------------------------------------------------------------
    print("\n--- Bypass Attack 4: Contradictory Evidence with Biased Extractor ---")
    try:
        ev_1 = Evidence(
            evidence_id="EV-1",
            source_id="DOC-1",
            source_type="document",
            uri="file:///1.md",
            content="System is online.",
            content_hash="h1",
            source_path="/1.md",
            chunk_index=0,
            start_offset=0,
            end_offset=17,
            metadata={},
            created_at="2026-09-01T00:00:00Z",
        )
        ev_2 = Evidence(
            evidence_id="EV-2",
            source_id="DOC-2",
            source_type="document",
            uri="file:///2.md",
            content="System is shutdown.",
            content_hash="h2",
            source_path="/2.md",
            chunk_index=0,
            start_offset=0,
            end_offset=19,
            metadata={},
            created_at="2026-09-01T00:00:00Z",
        )
        edge_contra = EvidenceEdge(
            source_evidence_id="EV-1",
            target_evidence_id="EV-2",
            relationship_type=RelationshipType.CONTRADICTS,
            basis="Direct state contradiction",
            confidence=1.0,
            derived_by=EdgeDerivationType.DETERMINISTIC_REFERENCE,
        )
        pkg_contra = EvidencePackage(
            objective="Verify system state",
            termination_reason="SUFFICIENT",
            controller_verified=True,
            budget_summary={},
            evidence_items=[ev_1, ev_2],
            graph_edges=[edge_contra],
            gap_history=[],
            gaps=[],
        )

        # Biased agent attempts to output only the "online" side
        def biased_agent(obj, evs):
            return [Claim(claim_id="c_bias", statement="System is definitely online", evidence_ids=["EV-1"])]

        res_contra = synthesizer.synthesize(pkg_contra, agent_claim_extractor_fn=biased_agent)
        assert res_contra.status == SynthesisStatus.RECONCILIATION_REQUIRED
        assert len(res_contra.claims) == 0
        assert res_contra.reconciliation_report is not None
        assert len(res_contra.reconciliation_report.opposing_claims) == 1

        record_pass("BYPASS_4", "ContradictionEnforcement", "Biased agent preempted by Gate 2; RECONCILIATION_REQUIRED returned.")
    except Exception as e:
        record_fail("BYPASS_4", "ContradictionEnforcement", "Contradiction bypassed by biased agent", e)

    # -------------------------------------------------------------------------
    # BYPASS ATTACK 5: CITATIONS POINTING TO UNADMITTED EVIDENCE
    # -------------------------------------------------------------------------
    print("\n--- Bypass Attack 5: Citations Must Point Only to Admitted Evidence ---")
    try:
        # Resolve citations for an evidence ID not present in evidence_index
        fake_ids = ["NONEXISTENT_EV_1", "NONEXISTENT_EV_2"]
        cits, mapping = CitationResolver.resolve_citations_for_evidence_ids(fake_ids, {ev_valid.evidence_id: ev_valid})
        assert len(cits) == 0, f"Expected 0 citations, got {len(cits)}"
        assert len(mapping) == 0, f"Expected empty mapping, got {mapping}"

        record_pass("BYPASS_5", "CitationIntegrity", "CitationResolver refuses to generate citations for unindexed evidence IDs.")
    except Exception as e:
        record_fail("BYPASS_5", "CitationIntegrity", "CitationResolver generated citation for unadmitted ID", e)

    # -------------------------------------------------------------------------
    # BYPASS ATTACK 6: CAUSAL SELF-LOOP & CYCLIC EDGES
    # -------------------------------------------------------------------------
    print("\n--- Bypass Attack 6: Causal Self-Loops and Cycles ---")
    try:
        edge_self = EvidenceEdge(
            source_evidence_id="EV-100",
            target_evidence_id="EV-100",
            relationship_type=RelationshipType.DEPENDS_ON,
            basis="Self cycle",
            confidence=1.0,
            derived_by=EdgeDerivationType.DETERMINISTIC_REFERENCE,
        )
        pkg_self_causal = EvidencePackage(
            objective="Verify causal loop",
            termination_reason="SUFFICIENT",
            controller_verified=True,
            budget_summary={},
            evidence_items=[ev_valid],
            graph_edges=[edge_self],
            gap_history=[],
            gaps=[],
        )
        res_self_causal = synthesizer.synthesize(pkg_self_causal)
        assert res_self_causal.status == SynthesisStatus.SUCCESS
        assert len(res_self_causal.claims) == 1
        claim_0 = res_self_causal.claims[0]
        assert claim_0.claim_id not in claim_0.causal_predecessors, "Claim depends on itself!"

        record_pass("BYPASS_6", "CausalCycleGuard", "Self-loop edge cleanly filtered; claim does not list itself as predecessor.")
    except Exception as e:
        record_fail("BYPASS_6", "CausalCycleGuard", "Self-loop caused invalid causal dependency", e)

    # -------------------------------------------------------------------------
    # BYPASS ATTACK 7: SECRET LEAKAGE SANITIZATION
    # -------------------------------------------------------------------------
    print("\n--- Bypass Attack 7: Secret Leakage Defense ---")
    try:
        fake_pat = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"
        fake_bearer = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
        ev_secret = Evidence(
            evidence_id="EV-SEC",
            source_id="SECRET-DOC",
            source_type="jira",
            uri="https://jira.corp/SEC-1",
            content=f"Secret credentials: PAT={fake_pat} and Auth={fake_bearer}",
            content_hash="h_sec",
            source_path="SEC-1",
            chunk_index=0,
            start_offset=0,
            end_offset=95,
            metadata={},
            created_at="2026-09-01T00:00:00Z",
        )
        pkg_sec = EvidencePackage(
            objective="Inspect secrets",
            termination_reason="SUFFICIENT",
            controller_verified=True,
            budget_summary={},
            evidence_items=[ev_secret],
            graph_edges=[],
            gap_history=[],
            gaps=[],
        )
        res_sec = synthesizer.synthesize(pkg_sec)
        assert fake_pat not in res_sec.final_answer, "GitHub PAT was leaked in final answer!"
        assert fake_bearer not in res_sec.final_answer, "Bearer token was leaked in final answer!"
        assert "***REDACTED_PAT***" in res_sec.final_answer or "***REDACTED***" in res_sec.final_answer

        # Also verify JSON export does not contain unmasked PAT
        res_json = res_sec.model_dump_json()
        assert fake_pat not in res_json, "GitHub PAT leaked in SynthesisResult JSON export!"

        record_pass("BYPASS_7", "SecretLeakageDefense", "All secret PATs and Bearer tokens redacted from answer and JSON serialization.")
    except Exception as e:
        record_fail("BYPASS_7", "SecretLeakageDefense", "Secret leaked in synthesis output", e)

    # -------------------------------------------------------------------------
    # BYPASS ATTACK 8: DETERMINISTIC IDEMPOTENCY
    # -------------------------------------------------------------------------
    print("\n--- Bypass Attack 8: Deterministic Idempotency ---")
    try:
        res_1 = synthesizer.synthesize(pkg_spoof)
        res_2 = synthesizer.synthesize(pkg_spoof)
        assert res_1.final_answer == res_2.final_answer, "Final answer is non-deterministic across identical runs!"
        assert [c.claim_id for c in res_1.claims] == [c.claim_id for c in res_2.claims]
        assert [c.citation_id for c in res_1.citations] == [c.citation_id for c in res_2.citations]
        assert [c.content_hash for c in res_1.citations] == [c.content_hash for c in res_2.citations]

        record_pass("BYPASS_8", "DeterministicIdempotency", "100% byte-identical claims, citations, and answers across repeated invocations.")
    except Exception as e:
        record_fail("BYPASS_8", "DeterministicIdempotency", "Non-deterministic synthesis output detected", e)

    # -------------------------------------------------------------------------
    # BYPASS ATTACK 9: DOMAIN / PROVIDER HARDCODING AUDIT
    # -------------------------------------------------------------------------
    print("\n--- Bypass Attack 9: Provider & Domain Neutrality Audit ---")
    try:
        synthesis_files = [
            Path("backend/synthesis/synthesizer.py"),
            Path("backend/synthesis/models.py"),
            Path("backend/synthesis/citations.py"),
        ]
        forbidden_regex = re.compile(r"\b(jira|github|linear|slack|phoenix|nova)\b", re.IGNORECASE)
        hardcoded_matches = []
        for f in synthesis_files:
            text = f.read_text(encoding="utf-8")
            matches = forbidden_regex.findall(text)
            if matches:
                hardcoded_matches.append((f.name, matches))

        assert len(hardcoded_matches) == 0, f"Found hardcoded domain/provider tokens in synthesis layer: {hardcoded_matches}"
        record_pass("BYPASS_9", "ProviderNeutralityAudit", "Zero hardcoded provider or domain strings found in backend/synthesis/.")
    except Exception as e:
        record_fail("BYPASS_9", "ProviderNeutralityAudit", "Hardcoded provider strings discovered", e)

    # -------------------------------------------------------------------------
    # SUMMARY
    # -------------------------------------------------------------------------
    print("\n" + "=" * 80)
    print("VERIFICATION SUMMARY")
    print("=" * 80)
    print(f"Total Tests Run:    {len(passes) + len(failures)}")
    print(f"Passed Tests:       {len(passes)}")
    print(f"Failed Tests:       {len(failures)}")
    print(f"Warnings / Limits:  {len(warnings)}")

    if failures:
        print("\nFAILURES ENCOUNTERED:")
        for f in failures:
            print(f"  - [{f['id']}] {f['name']}: {f['description']} (Error: {f['error']})")
    else:
        print("\nALL VERIFICATION & ADVERSARIAL BYPASS TESTS PASSED.")

    return len(failures) == 0


if __name__ == "__main__":
    success = run_strict_verification()
    sys.exit(0 if success else 1)
