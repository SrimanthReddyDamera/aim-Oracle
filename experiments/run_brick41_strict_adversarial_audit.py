"""
BRICK 4.1 STRICT ADVERSARIAL AUDIT RUNNER
=========================================
Adversarial attack harness designed to systematically stress-test and attempt to break:
- Gate 1: Controller Verification Gate
- Gate 2: Contradiction / Reconciliation Gate
- Gate 3: Claim Extraction & Evidence Grounding Gate
- Gate 4: Causal Graph Linking Gate
- Gate 5: Deterministic Citation Resolution & Provenance Gate
- Epistemic Honesty & Fallbacks
- Provider & Domain Neutrality
- The 3 Brick 4.1 Remediations (Controller Gap Lifecycle, Empty Candidate Claim Validation, Heading Sanitization)
"""

import hashlib
import json
import os
import re
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

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


class AdversarialAuditSuite:
    def __init__(self):
        self.results = []
        self.weaknesses = []

    def record_result(self, test_name: str, gate: str, status: str, details: str, severity: str = "NONE", potential_hallucination: bool = False):
        res = {
            "test_name": test_name,
            "gate": gate,
            "status": status,
            "details": details,
            "severity": severity,
            "potential_hallucination": potential_hallucination,
        }
        self.results.append(res)
        if status == "FAIL":
            self.weaknesses.append(res)
        symbol = "[PASS]" if status == "PASS" else "[FAIL]"
        print(f"  {symbol} {test_name}: {details}")

    def create_mock_evidence(
        self,
        eid: str,
        source_type: str = "custom_provider",
        source_id: str = "RES-100",
        uri: Optional[str] = "https://internal.service.net/res/100",
        content: str = "Production cluster east is running version 2.4.1.",
        source_path: Optional[str] = "/var/data/cluster.json",
        start_offset: int = 0,
        end_offset: int = 50,
    ) -> Evidence:
        content_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()
        return Evidence(
            evidence_id=eid,
            source_id=source_id,
            source_type=source_type,
            uri=uri,
            content=content,
            content_hash=content_hash,
            source_path=source_path,
            chunk_index=0,
            start_offset=start_offset,
            end_offset=end_offset,
            metadata={"environment": "production"},
            created_at="2026-09-01T00:00:00Z",
        )

    # -------------------------------------------------------------------------
    # ATTACK GATE 1: CONTROLLER VERIFICATION GATE
    # -------------------------------------------------------------------------
    def attack_gate_1(self):
        print("\n" + "="*80)
        print("ATTACKING GATE 1: CONTROLLER VERIFICATION & GAP STATE")
        print("="*80)
        synthesizer = EvidenceSynthesizer()
        ev = self.create_mock_evidence("EV-1")

        # 1.1: controller_verified=False with evidence present
        pkg_unverified = EvidencePackage(
            objective="Verify payment service state",
            termination_reason="BUDGET_EXHAUSTED_MAX_HOPS",
            controller_verified=False,
            budget_summary={},
            evidence_items=[ev],
            graph_edges=[],
            gap_history=[],
            gaps=[],
        )
        res = synthesizer.synthesize(pkg_unverified)
        if res.status == SynthesisStatus.INSUFFICIENT_EVIDENCE and len(res.claims) == 0:
            self.record_result("Gate1_UnverifiedWithEvidence", "Gate 1", "PASS", "Rejected unverified package; returned INSUFFICIENT_EVIDENCE with 0 claims.")
        else:
            self.record_result("Gate1_UnverifiedWithEvidence", "Gate 1", "FAIL", f"Produced {res.status} with {len(res.claims)} claims when controller_verified=False", severity="CRITICAL", potential_hallucination=True)

        # 1.2: controller_verified=True BUT open blocking gap present
        open_blocking_gap = InformationGap(
            gap_id="GAP-BLOCK-1",
            gap_type=GapType.PREREQUISITE,
            is_blocking=True,
            description="Missing database credentials specification",
            target_entity="DB Credentials",
            required_information="Proof of credential rotation",
            status=GapStatus.OPEN,
        )
        pkg_open_gap = EvidencePackage(
            objective="Verify payment service state",
            termination_reason="SUFFICIENT",
            controller_verified=True,
            budget_summary={},
            evidence_items=[ev],
            graph_edges=[],
            gap_history=[],
            gaps=[open_blocking_gap],
        )
        res = synthesizer.synthesize(pkg_open_gap)
        if res.status == SynthesisStatus.INSUFFICIENT_EVIDENCE and len(res.claims) == 0 and res.insufficient_report and len(res.insufficient_report.open_gaps) == 1:
            self.record_result("Gate1_OpenBlockingGapBlocksSuccess", "Gate 1", "PASS", "Blocked authoritative answer due to open blocking gap despite controller_verified=True.")
        else:
            self.record_result("Gate1_OpenBlockingGapBlocksSuccess", "Gate 1", "FAIL", f"Synthesizer allowed {res.status} despite open blocking gap.", severity="CRITICAL", potential_hallucination=True)

        # 1.3: controller_verified=True BUT empty evidence
        pkg_empty_ev = EvidencePackage(
            objective="Verify payment service state",
            termination_reason="SUFFICIENT",
            controller_verified=True,
            budget_summary={},
            evidence_items=[],
            graph_edges=[],
            gap_history=[],
            gaps=[],
        )
        res = synthesizer.synthesize(pkg_empty_ev)
        if res.status == SynthesisStatus.INSUFFICIENT_EVIDENCE:
            self.record_result("Gate1_EmptyEvidenceRejected", "Gate 1", "PASS", "Rejected empty evidence package with INSUFFICIENT_EVIDENCE.")
        else:
            self.record_result("Gate1_EmptyEvidenceRejected", "Gate 1", "FAIL", f"Allowed {res.status} with empty evidence.", severity="HIGH", potential_hallucination=True)

        # 1.4: Non-blocking open gap should NOT block synthesis if controller_verified=True
        open_non_blocking_gap = InformationGap(
            gap_id="GAP-INFO-1",
            gap_type=GapType.STATE_VERIFICATION,
            is_blocking=False,
            description="Optional telemetry latency metrics",
            target_entity="Latency Metrics",
            required_information="P99 latency measurements",
            status=GapStatus.OPEN,
        )
        pkg_non_blocking = EvidencePackage(
            objective="Verify payment service state",
            termination_reason="SUFFICIENT",
            controller_verified=True,
            budget_summary={},
            evidence_items=[ev],
            graph_edges=[],
            gap_history=[],
            gaps=[open_non_blocking_gap],
        )
        res = synthesizer.synthesize(pkg_non_blocking)
        if res.status == SynthesisStatus.SUCCESS and len(res.claims) == 1:
            self.record_result("Gate1_NonBlockingGapPermitsSuccess", "Gate 1", "PASS", "Non-blocking informational gap correctly did not prevent synthesis.")
        else:
            self.record_result("Gate1_NonBlockingGapPermitsSuccess", "Gate 1", "FAIL", f"Non-blocking gap caused unexpected status: {res.status}", severity="MEDIUM")

    # -------------------------------------------------------------------------
    # ATTACK GATE 2: CONTRADICTIONS & ARBITRATION
    # -------------------------------------------------------------------------
    def attack_gate_2(self):
        print("\n" + "="*80)
        print("ATTACKING GATE 2: CONTRADICTIONS & RECONCILIATION")
        print("="*80)
        synthesizer = EvidenceSynthesizer()
        ev_a = self.create_mock_evidence("EV-A", source_type="config_db", content="Redis v7 is active in cluster.")
        ev_b = self.create_mock_evidence("EV-B", source_type="ticket_system", content="Redis v7 was rolled back to v6.")

        # 2.1: Direct CONTRADICTS edge between heterogeneous providers
        contradict_edge = EvidenceEdge(
            source_evidence_id="EV-A",
            target_evidence_id="EV-B",
            relationship_type=RelationshipType.CONTRADICTS,
            basis="Configuration claims Redis v7 active, but incident ticket confirms rollback to v6",
            confidence=1.0,
            derived_by=EdgeDerivationType.DETERMINISTIC_REFERENCE,
        )
        pkg_contra = EvidencePackage(
            objective="Determine active Redis version",
            termination_reason="SUFFICIENT",
            controller_verified=True,
            budget_summary={},
            evidence_items=[ev_a, ev_b],
            graph_edges=[contradict_edge],
            gap_history=[],
            gaps=[],
        )

        # Inject an adversarial claim extractor that attempts to pick side A
        def biased_extractor(obj, evs):
            return [
                Claim(
                    claim_id="c_biased",
                    statement="Redis v7 is confirmed active.",
                    evidence_ids=["EV-A"],
                )
            ]

        res = synthesizer.synthesize(pkg_contra, agent_claim_extractor_fn=biased_extractor)
        if res.status == SynthesisStatus.RECONCILIATION_REQUIRED and len(res.claims) == 0:
            assert res.reconciliation_report is not None
            assert len(res.reconciliation_report.opposing_claims) == 1
            self.record_result("Gate2_ContradictionPreventsOneSidedBias", "Gate 2", "PASS", "CONTRADICTS edge preempted biased extractor; forced RECONCILIATION_REQUIRED.")
        else:
            self.record_result("Gate2_ContradictionPreventsOneSidedBias", "Gate 2", "FAIL", f"Contradiction was ignored or bypassed; status={res.status}", severity="CRITICAL", potential_hallucination=True)

        # 2.2: GapStatus.RECONCILIATION_REQUIRED present without edge
        reconcile_gap = InformationGap(
            gap_id="GAP-RECON-1",
            gap_type=GapType.CONTRADICTION_RECONCILIATION,
            is_blocking=True,
            description="Reconcile version discrepancy",
            target_entity="Redis Version",
            required_information="Authoritative final version",
            status=GapStatus.RECONCILIATION_REQUIRED,
            conflicting_evidence_ids=["EV-A", "EV-B"],
        )
        pkg_recon_gap = EvidencePackage(
            objective="Determine active Redis version",
            termination_reason="SUFFICIENT",
            controller_verified=True,
            budget_summary={},
            evidence_items=[ev_a, ev_b],
            graph_edges=[],
            gap_history=[],
            gaps=[reconcile_gap],
        )
        res_gap = synthesizer.synthesize(pkg_recon_gap)
        if res_gap.status == SynthesisStatus.RECONCILIATION_REQUIRED:
            self.record_result("Gate2_ReconciliationGapEnforced", "Gate 2", "PASS", "Reconciliation gap independently triggered RECONCILIATION_REQUIRED.")
        else:
            self.record_result("Gate2_ReconciliationGapEnforced", "Gate 2", "FAIL", f"Reconciliation gap ignored; status={res_gap.status}", severity="HIGH")

    # -------------------------------------------------------------------------
    # ATTACK GATE 3: UNSUPPORTED CLAIMS & GROUNDING GATE
    # -------------------------------------------------------------------------
    def attack_gate_3(self):
        print("\n" + "="*80)
        print("ATTACKING GATE 3: CLAIM EXTRACTION & GROUNDING GATE")
        print("="*80)
        synthesizer = EvidenceSynthesizer()
        ev_real = self.create_mock_evidence("EV-REAL-1", content="Cluster latency is 42ms.")

        pkg = EvidencePackage(
            objective="Verify latency",
            termination_reason="SUFFICIENT",
            controller_verified=True,
            budget_summary={},
            evidence_items=[ev_real],
            graph_edges=[],
            gap_history=[],
            gaps=[],
        )

        # 3.1: Completely fabricated evidence ID
        def extractor_fabricated(obj, evs):
            return [
                Claim(claim_id="c1", statement="Real claim", evidence_ids=["EV-REAL-1"]),
                Claim(claim_id="c2", statement="Fabricated claim", evidence_ids=["NONEXISTENT_EVID_999"]),
            ]
        res = synthesizer.synthesize(pkg, agent_claim_extractor_fn=extractor_fabricated)
        if len(res.claims) == 1 and res.claims[0].claim_id == "c1":
            self.record_result("Gate3_FabricatedIdStripped", "Gate 3", "PASS", "Fabricated evidence ID was completely stripped from claims.")
        else:
            self.record_result("Gate3_FabricatedIdStripped", "Gate 3", "FAIL", f"Fabricated ID leaked into claims: {[c.claim_id for c in res.claims]}", severity="CRITICAL", potential_hallucination=True)

        # 3.2: Partial hallucination (claim with mixed real and fake IDs)
        def extractor_mixed(obj, evs):
            return [
                Claim(claim_id="c_mixed", statement="Mixed claim", evidence_ids=["EV-REAL-1", "FAKE_ID_888"]),
            ]
        res_mixed = synthesizer.synthesize(pkg, agent_claim_extractor_fn=extractor_mixed)
        if len(res_mixed.claims) == 1 and res_mixed.claims[0].evidence_ids == ["EV-REAL-1"]:
            self.record_result("Gate3_MixedEvidenceIdPruned", "Gate 3", "PASS", "Invalid evidence ID pruned from mixed claim while keeping valid ID.")
        else:
            self.record_result("Gate3_MixedEvidenceIdPruned", "Gate 3", "FAIL", f"Invalid ID retained in mixed claim: {res_mixed.claims[0].evidence_ids}", severity="HIGH", potential_hallucination=True)

        # 3.3: Empty evidence list on candidate claim
        def extractor_empty(obj, evs):
            return [
                Claim(claim_id="c_empty", statement="Totally unsupported assertion", evidence_ids=[]),
            ]
        res_empty = synthesizer.synthesize(pkg, agent_claim_extractor_fn=extractor_empty)
        if res_empty.status == SynthesisStatus.INSUFFICIENT_EVIDENCE and len(res_empty.claims) == 0:
            self.record_result("Gate3_EmptyEvidenceListHandled", "Gate 3", "PASS", "Claim with empty evidence list gracefully converted to INSUFFICIENT_EVIDENCE without crash.")
        else:
            self.record_result("Gate3_EmptyEvidenceListHandled", "Gate 3", "FAIL", f"Unexpected output for empty evidence candidate claim: {res_empty.status}", severity="HIGH", potential_hallucination=True)

        # 3.4: Duplicated evidence IDs in candidate claim
        def extractor_dups(obj, evs):
            return [
                Claim(claim_id="c_dup", statement="Duplicated id claim", evidence_ids=["EV-REAL-1", "EV-REAL-1"]),
            ]
        res_dups = synthesizer.synthesize(pkg, agent_claim_extractor_fn=extractor_dups)
        if len(res_dups.citations) == 1:
            self.record_result("Gate3_DuplicateEvidenceDeduplicated", "Gate 3", "PASS", "Duplicate evidence references properly resolved to a single citation.")
        else:
            self.record_result("Gate3_DuplicateEvidenceDeduplicated", "Gate 3", "FAIL", f"Citation duplicate count: {len(res_dups.citations)}", severity="LOW")

    # -------------------------------------------------------------------------
    # ATTACK GATE 4: CAUSAL GRAPH LINKING
    # -------------------------------------------------------------------------
    def attack_gate_4(self):
        print("\n" + "="*80)
        print("ATTACKING GATE 4: CAUSAL GRAPH LINKING")
        print("="*80)
        synthesizer = EvidenceSynthesizer()
        ev_deploy = self.create_mock_evidence("EV-DEPLOY", content="Deployment step 2 executed.")
        ev_prereq = self.create_mock_evidence("EV-PREREQ", content="Database migration step 1 completed.")

        dep_edge = EvidenceEdge(
            source_evidence_id="EV-DEPLOY",
            target_evidence_id="EV-PREREQ",
            relationship_type=RelationshipType.DEPENDS_ON,
            basis="Deployment requires prior migration",
            confidence=1.0,
            derived_by=EdgeDerivationType.DETERMINISTIC_REFERENCE,
        )

        pkg = EvidencePackage(
            objective="Verify deployment sequence",
            termination_reason="SUFFICIENT",
            controller_verified=True,
            budget_summary={},
            evidence_items=[ev_deploy, ev_prereq],
            graph_edges=[dep_edge],
            gap_history=[],
            gaps=[],
        )

        # 4.1: Normal causal mapping
        res = synthesizer.synthesize(pkg)
        c_deploy = next((c for c in res.claims if "EV-DEPLOY" in c.evidence_ids), None)
        c_prereq = next((c for c in res.claims if "EV-PREREQ" in c.evidence_ids), None)
        if c_deploy and c_prereq and c_prereq.claim_id in c_deploy.causal_predecessors:
            self.record_result("Gate4_CausalDependencyMapped", "Gate 4", "PASS", f"DEPENDS_ON correctly mapped {c_prereq.claim_id} as causal predecessor of {c_deploy.claim_id}.")
        else:
            self.record_result("Gate4_CausalDependencyMapped", "Gate 4", "FAIL", "Failed to map causal relationship.", severity="MEDIUM")

        # 4.2: Self-loop in DEPENDS_ON edge
        self_loop_edge = EvidenceEdge(
            source_evidence_id="EV-DEPLOY",
            target_evidence_id="EV-DEPLOY",
            relationship_type=RelationshipType.DEPENDS_ON,
            basis="Self loop",
            confidence=1.0,
            derived_by=EdgeDerivationType.DETERMINISTIC_REFERENCE,
        )
        pkg_self = EvidencePackage(
            objective="Verify self loop",
            termination_reason="SUFFICIENT",
            controller_verified=True,
            budget_summary={},
            evidence_items=[ev_deploy],
            graph_edges=[self_loop_edge],
            gap_history=[],
            gaps=[],
        )
        res_self = synthesizer.synthesize(pkg_self)
        if res_self.claims and res_self.claims[0].claim_id not in res_self.claims[0].causal_predecessors:
            self.record_result("Gate4_SelfLoopCycleGuarded", "Gate 4", "PASS", "Self-loop edge safely prevented claim from depending on itself.")
        else:
            self.record_result("Gate4_SelfLoopCycleGuarded", "Gate 4", "FAIL", "Claim allowed to list itself as causal predecessor.", severity="LOW")

        # 4.3: Edge pointing to missing evidence ID
        orphan_edge = EvidenceEdge(
            source_evidence_id="EV-DEPLOY",
            target_evidence_id="EV-NONEXISTENT",
            relationship_type=RelationshipType.DEPENDS_ON,
            basis="Points to missing evidence",
            confidence=1.0,
            derived_by=EdgeDerivationType.DETERMINISTIC_REFERENCE,
        )
        pkg_orphan = EvidencePackage(
            objective="Verify missing edge target",
            termination_reason="SUFFICIENT",
            controller_verified=True,
            budget_summary={},
            evidence_items=[ev_deploy],
            graph_edges=[orphan_edge],
            gap_history=[],
            gaps=[],
        )
        res_orphan = synthesizer.synthesize(pkg_orphan)
        if res_orphan.status == SynthesisStatus.SUCCESS and len(res_orphan.claims) == 1:
            self.record_result("Gate4_MissingEdgeTargetHandled", "Gate 4", "PASS", "Orphaned target evidence edge handled without exception.")
        else:
            self.record_result("Gate4_MissingEdgeTargetHandled", "Gate 4", "FAIL", "Exception or bad state on orphaned edge.", severity="LOW")

    # -------------------------------------------------------------------------
    # ATTACK GATE 5: CITATION RESOLVER & INTEGRITY
    # -------------------------------------------------------------------------
    def attack_gate_5(self):
        print("\n" + "="*80)
        print("ATTACKING GATE 5: CITATION INTEGRITY & EXTREME BOUNDARY CONDITIONS")
        print("="*80)

        # 5.1: Unicode & Multibyte characters
        multibyte_content = "🚀 Service állapot: üzemkész! 日本語のログ: 正常 (UTF-8 3-byte and 4-byte glyphs) éàô"
        ev_multi = self.create_mock_evidence("EV-MULTI", content=multibyte_content, start_offset=1024, end_offset=1120)
        cit_multi = CitationResolver.resolve_citation(ev_multi, citation_index=1)
        if cit_multi.content_hash == hashlib.sha256(multibyte_content.encode("utf-8")).hexdigest() and "🚀" in cit_multi.content_preview:
            self.record_result("Gate5_UnicodeMultibyteIntegrity", "Gate 5", "PASS", "Multibyte content hashed and previewed accurately.")
        else:
            self.record_result("Gate5_UnicodeMultibyteIntegrity", "Gate 5", "FAIL", "Multibyte content corrupted during citation resolution.", severity="HIGH")

        # 5.2: Empty content string
        ev_empty = self.create_mock_evidence("EV-EMPTY", content="", start_offset=0, end_offset=0)
        cit_empty = CitationResolver.resolve_citation(ev_empty, citation_index=2)
        if cit_empty.content_preview == "" and cit_empty.start_offset == 0 and cit_empty.end_offset == 0:
            self.record_result("Gate5_EmptyContentCitationHandled", "Gate 5", "PASS", "Empty content chunk resolved safely without error.")
        else:
            self.record_result("Gate5_EmptyContentCitationHandled", "Gate 5", "FAIL", "Empty content generated invalid citation.", severity="LOW")

        # 5.3: Exact byte offset preservation and disk slice match
        doc_path = Path("tests/test_data/nova_corpus/DOC-NOVA-PAYMENT.md")
        if doc_path.exists():
            raw_bytes = doc_path.read_bytes()
            # Slice first 56 bytes
            expected_slice = raw_bytes[0:56].decode("utf-8")
            ev_disk = Evidence(
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
            cit_disk = CitationResolver.resolve_citation(ev_disk, citation_index=3)
            slice_from_offsets = raw_bytes[cit_disk.start_offset:cit_disk.end_offset].decode("utf-8")
            if slice_from_offsets == ev_disk.content:
                self.record_result("Gate5_ByteOffsetDiskFidelity", "Gate 5", "PASS", "Citation byte offsets [0:56] perfectly slice source file from disk.")
            else:
                self.record_result("Gate5_ByteOffsetDiskFidelity", "Gate 5", "FAIL", "Byte offset disk mismatch.", severity="CRITICAL")

        # 5.4: Footnote Markdown rendering
        foot = CitationResolver.render_footnote_block([cit_multi])
        if "### Evidence Provenance & Citations:" in foot and cit_multi.content_hash[:12] in foot:
            self.record_result("Gate5_FootnoteBlockRendered", "Gate 5", "PASS", "Footnote block rendered with cryptographic hash and offsets.")
        else:
            self.record_result("Gate5_FootnoteBlockRendered", "Gate 5", "FAIL", "Footnote block missing required provenance markers.", severity="HIGH")

    # -------------------------------------------------------------------------
    # ATTACK REMEDIATIONS: BRICK 4.1 VERIFICATION
    # -------------------------------------------------------------------------
    def attack_brick41_remediations(self):
        print("\n" + "="*80)
        print("ATTACKING BRICK 4.1 REMEDIATIONS (GAP LIFECYCLE, EMPTY CLAIMS, SANITIZATION)")
        print("="*80)

        # R1: Verify Controller cannot certify sufficiency if a blocking prerequisite gap is NOT satisfied
        retriever = SQLiteFTS5Retriever(":memory:")
        doc_c = self.create_mock_evidence("EV-DOC", content="Project Phoenix payment gateway architecture specification.")
        retriever.index_evidence([doc_c])

        controller = InvestigationController(retriever=retriever)
        session = controller.run_investigation(
            objective="Verify non-existent subsystem requirement XYZ",
            # Agent tries to claim sufficiency prematurely
            reasoning_agent_fn=lambda s: (True, "Agent falsely claims all good", [], []),
            initial_k=1,
        )
        # Does the controller allow controller_verified=True if a gap cannot be verified?
        # Note: in this objective, let's see if the controller allowed false sufficiency
        blocking_open = [g for g in session.gaps if g.is_blocking and g.gap_id != "GAP-ROOT-1" and g.status in [GapStatus.OPEN, GapStatus.INVESTIGATING, GapStatus.UNRESOLVED, GapStatus.BLOCKED]]
        if session.controller_verified is True and blocking_open:
            self.record_result("Remediation1_NoCoexistenceOfSufficiencyAndOpenBlockingGap", "Remediation 1", "FAIL", f"controller_verified=True coexists with open blocking gaps: {[g.gap_id for g in blocking_open]}", severity="CRITICAL", potential_hallucination=True)
        else:
            self.record_result("Remediation1_NoCoexistenceOfSufficiencyAndOpenBlockingGap", "Remediation 1", "PASS", "Invariance upheld: controller_verified=True cannot coexist with open blocking gaps.")

        # R2: Candidate claim with evidence_ids=[]
        c_empty = Claim(claim_id="test_empty", statement="No evidence backing", evidence_ids=[])
        if c_empty.evidence_ids == []:
            self.record_result("Remediation2_ClaimAllowsEmptyListAtInstantiation", "Remediation 2", "PASS", "Claim model successfully accepts evidence_ids=[] without Pydantic ValidationError.")
        else:
            self.record_result("Remediation2_ClaimAllowsEmptyListAtInstantiation", "Remediation 2", "FAIL", "Claim model rejected empty list.", severity="HIGH")

        # R3: Objective header sanitization & length bounding
        malicious_input = "## Injection \n\n```python\nimport os; os.system('rm -rf')\n``` [Link](http://evil.com) " + ("X" * 150)
        sanitized = _sanitize_heading_text(malicious_input, max_length=80)
        if len(sanitized) <= 85 and "\n" not in sanitized and "\\#" in sanitized and "\\[" in sanitized:
            self.record_result("Remediation3_ObjectiveHeadingSanitized", "Remediation 3", "PASS", f"Heading safely escaped Markdown syntax and constrained length: '{sanitized}'")
        else:
            self.record_result("Remediation3_ObjectiveHeadingSanitized", "Remediation 3", "FAIL", f"Unsafe sanitization output: '{sanitized}'", severity="HIGH")

    # -------------------------------------------------------------------------
    # ATTACK PROVIDER NEUTRALITY: GENERIC UNSEEN ADAPTER EVIDENCE
    # -------------------------------------------------------------------------
    def attack_provider_neutrality(self):
        print("\n" + "="*80)
        print("ATTACKING PROVIDER NEUTRALITY (GENERIC MOCK SOURCES)")
        print("="*80)
        synthesizer = EvidenceSynthesizer()

        # Create evidence from completely unseen providers: "datadog_metric", "pagerduty_incident", "cmdb_asset"
        ev_dd = self.create_mock_evidence("EV-DD-1", source_type="datadog_metric", source_id="metric_cpu_util", uri="https://app.datadoghq.com/metric/cpu", content="CPU utilization is 98.2% across workers.")
        ev_pd = self.create_mock_evidence("EV-PD-1", source_type="pagerduty_incident", source_id="INC-PAGER-99", uri="https://company.pagerduty.com/incidents/99", content="High latency trigger fired at 04:12 UTC.")
        ev_cm = self.create_mock_evidence("EV-CM-1", source_type="cmdb_asset", source_id="SRV-PROD-01", uri="https://cmdb.corp/ci/SRV-PROD-01", content="Primary host in region us-central-1.")

        pkg_generic = EvidencePackage(
            objective="Investigate alert cascade across Datadog, PagerDuty, and CMDB",
            termination_reason="SUFFICIENT",
            controller_verified=True,
            budget_summary={},
            evidence_items=[ev_dd, ev_pd, ev_cm],
            graph_edges=[],
            gap_history=[],
            gaps=[],
        )

        res = synthesizer.synthesize(pkg_generic)
        providers_cited = {c.source_type for c in res.citations}
        if res.status == SynthesisStatus.SUCCESS and providers_cited == {"datadog_metric", "pagerduty_incident", "cmdb_asset"}:
            self.record_result("ProviderNeutrality_UnseenSourcesHandled", "Provider Neutrality", "PASS", f"Seamlessly synthesized citations across custom providers: {providers_cited}")
        else:
            self.record_result("ProviderNeutrality_UnseenSourcesHandled", "Provider Neutrality", "FAIL", f"Failed with custom providers; cited={providers_cited}, status={res.status}", severity="HIGH")

    def run_all(self):
        self.attack_gate_1()
        self.attack_gate_2()
        self.attack_gate_3()
        self.attack_gate_4()
        self.attack_gate_5()
        self.attack_brick41_remediations()
        self.attack_provider_neutrality()

        total = len(self.results)
        passed = sum(1 for r in self.results if r["status"] == "PASS")
        failed = sum(1 for r in self.results if r["status"] == "FAIL")

        print("\n" + "="*80)
        print(f"ADVERSARIAL AUDIT COMPLETE: {passed}/{total} PASSED ({failed} FAILED)")
        print("="*80)
        return self.results, self.weaknesses


if __name__ == "__main__":
    suite = AdversarialAuditSuite()
    suite.run_all()
