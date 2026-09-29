"""
ORACLE — PHASE 2.2.1: DOMAIN TRANSFER ADVERSARIAL VERIFICATION HARNESS
======================================================================
Comprehensive verification suite testing domain neutrality, entity diversity,
authority diversity, contradiction/supersession transfer, gap resolution transfer,
domain substitution, AST/string audit, and behavioral coupling attacks across:
1. Software Deployment
2. Finance
3. Logistics
4. Manufacturing
5. Healthcare
6. Project / Personal Planning

VERIFICATION-ONLY HARNESS — NO PRODUCTION CODE MODIFIED.
"""

import ast
import os
import pathlib
import re
import sys
from typing import Any, Dict, List, Set, Tuple

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from backend.evidence.models import Evidence
from backend.investigation.controller import (
    InvestigationController,
    InvestigationBudget,
    InvestigationSession,
    InvestigationState,
)
from backend.investigation.entity_scanner import EntityScanner, TOKEN_PATTERNS
from backend.investigation.models import (
    GapStatus,
    GapType,
    InformationGap,
    RelationshipType,
)
from backend.investigation.temporal_scanner import TemporalConflictScanner
def make_evidence(eid: str, content: str, source_id: str = "TEST-SRC", source_type: str = "document", created_at: str = "2026-10-21T12:00:00Z") -> Evidence:
    return Evidence(
        evidence_id=eid,
        source_id=source_id,
        source_type=source_type,
        content=content,
        content_hash=f"hash_{eid}",
        source_path=f"path/{source_id}",
        chunk_index=0,
        start_offset=0,
        end_offset=len(content),
        created_at=created_at,
    )


class MockRetriever:
    def __init__(self, items: List[Evidence] = None):
        self.items = items or []

    def search(self, query: str, k: int = 10):
        return [(item, 1.0) for item in self.items[:k]], {}


# ==============================================================================
# 1. DOMAIN TEST SCENARIO DEFINITIONS
# ==============================================================================

DOMAINS = {
    "software": {
        "entity_ids": ["BUILD-2026-09", "SERVICE_A", "NODE-9B"],
        "authority_phrases": ["Release approval: approved", "Architecture decision: accepted"],
        "opposing_states": ("deployed", "failed"),
        "evidence_old": "Specification defines deployment parameters for SERVICE_A on NODE-9B with version 1.0.",
        "evidence_new": "Active operational status: SERVICE_A deployed on NODE-9B with version 2.0.",
        "contradiction_a": "Deployment status for SERVICE_A: deployed and running.",
        "contradiction_b": "Deployment status for SERVICE_A: failed and terminated.",
        "reconciled": "Meeting #12 decision: approved rollback of SERVICE_A to version 1.0.",
    },
    "finance": {
        "entity_ids": ["ACCOUNT-77", "POLICY-17", "TRANSACTION-8812"],
        "authority_phrases": ["Board decision: approved", "Compliance ruling: approved", "Signed policy decision: accepted"],
        "opposing_states": ("authorized", "frozen"),
        "evidence_old": "Policy specifies standard transaction limit of $10,000 for ACCOUNT-77.",
        "evidence_new": "Compliance ruling: approved updated transaction limit of $50,000 for ACCOUNT-77.",
        "contradiction_a": "Account status for ACCOUNT-77: active and authorized.",
        "contradiction_b": "Account status for ACCOUNT-77: frozen and blocked.",
        "reconciled": "Board decision: approved unfreezing of ACCOUNT-77 following audit.",
    },
    "logistics": {
        "entity_ids": ["ORDER-8842", "ROUTE-NORTH", "CARRIER-9B"],
        "authority_phrases": ["Operations disposition: approved", "Logistics controller decision: accepted"],
        "opposing_states": ("dispatched", "halted"),
        "evidence_old": "Route instructions dictate delivery via ROUTE-NORTH for ORDER-8842.",
        "evidence_new": "Operations disposition: approved rerouting of ORDER-8842 via ROUTE-SOUTH.",
        "contradiction_a": "Consignment status for ORDER-8842: dispatched and in-transit.",
        "contradiction_b": "Consignment status for ORDER-8842: halted and delayed.",
        "reconciled": "Logistics controller decision: approved priority clearance for ORDER-8842.",
    },
    "manufacturing": {
        "entity_ids": ["MACHINE-07", "LINE-4", "SPEC-TOLERANCE-01"],
        "authority_phrases": ["Quality board decision: approved", "Plant manager approval: approved"],
        "opposing_states": ("running", "stopped"),
        "evidence_old": "Process manual dictates operation speed at 1200 rpm for MACHINE-07.",
        "evidence_new": "Plant manager approval: approved operating speed of 900 rpm for MACHINE-07.",
        "contradiction_a": "Operating state for MACHINE-07: running and calibrated.",
        "contradiction_b": "Operating state for MACHINE-07: stopped and maintenance-required.",
        "reconciled": "Quality board decision: approved recalibration for MACHINE-07.",
    },
    "healthcare": {
        "entity_ids": ["CASE-4821", "PATIENT-301", "PROTOCOL-9"],
        "authority_phrases": ["Clinical review decision: approved", "Regulatory determination: accepted"],
        "opposing_states": ("administered", "suspended"),
        "evidence_old": "Clinical protocol dictates baseline administration of medication for CASE-4821.",
        "evidence_new": "Regulatory determination: accepted revised dosage guidelines for CASE-4821.",
        "contradiction_a": "Clinical status for CASE-4821: active treatment administered.",
        "contradiction_b": "Clinical status for CASE-4821: treatment suspended due to allergy.",
        "reconciled": "Clinical review decision: approved alternative treatment for CASE-4821.",
    },
    "project_planning": {
        "entity_ids": ["MILESTONE-Q3", "TASK-12", "SPRINT-44"],
        "authority_phrases": ["Steering committee decision: approved", "Managerial approval: accepted"],
        "opposing_states": ("completed", "blocked"),
        "evidence_old": "Project charter scheduled delivery of MILESTONE-Q3 for August 15.",
        "evidence_new": "Steering committee decision: approved shifting MILESTONE-Q3 to September 30.",
        "contradiction_a": "Status for MILESTONE-Q3: completed on schedule.",
        "contradiction_b": "Status for MILESTONE-Q3: blocked by external dependencies.",
        "reconciled": "Managerial approval: accepted scope re-allocation for MILESTONE-Q3.",
    },
}


# ==============================================================================
# HARNESS EXECUTION
# ==============================================================================

def run_tests():
    print("=" * 80)
    print("ORACLE — PHASE 2.2.1 DOMAIN TRANSFER ADVERSARIAL VERIFICATION")
    print("=" * 80)
    
    findings = []
    
    # --------------------------------------------------------------------------
    # 1. ENTITY FORMAT DIVERSITY & CLASSIFICATION AUDIT
    # --------------------------------------------------------------------------
    print("\n[TEST SECTION 1] ENTITY FORMAT DIVERSITY & CLASSIFICATION AUDIT")
    test_entities = [
        ("POLICY-17", "Finance policy"),
        ("CASE-4821", "Healthcare clinical case"),
        ("ORDER-8842", "Logistics order"),
        ("MACHINE-07", "Manufacturing machine"),
        ("BUILD-2026-09", "Software build number"),
        ("ACCOUNT-77", "Financial account"),
        ("SERVICE_A", "Software service with underscore"),
        ("NODE-9B", "Cluster node with alphanumeric suffix"),
        ("REGION-EU-WEST", "Multi-segment hyphenated region"),
        ("Warehouse Hub Alpha", "Natural language entity"),
    ]
    
    scanner = EntityScanner()
    for ent, desc in test_entities:
        category = scanner.classify_token(ent)
        extracted = scanner.extract_references(f"Refers to {ent} for operational processing.")
        ev = make_evidence(f"DOC-{ent}", f"Authoritative record: {ent} is verified.", source_id=f"SRC-{ent}")
        is_auth = scanner.is_authoritative_resolution(ent, ev)
        
        print(f"  Entity: {ent:22} | Category: {category:14} | Extracted: {bool(extracted)} | is_auth: {is_auth}")
        
        if category in ["UNKNOWN", "GENERIC_TICKET"] and ent not in ["Warehouse Hub Alpha"]:
            # Check if this token is tracked by find_unresolved_references
            dummy_ev = make_evidence("E1", f"Requires decision on {ent}.", source_id="DOC-REF")
            unres = scanner.find_unresolved_references({dummy_ev.evidence_id: dummy_ev})
            if ent not in unres:
                findings.append({
                    "section": "1. ENTITY FORMAT DIVERSITY",
                    "severity": "COUPLING_DEFECT",
                    "entity": ent,
                    "issue": f"Token '{ent}' classified as '{category}' and omitted from find_unresolved_references",
                    "location": "backend/investigation/entity_scanner.py:find_unresolved_references",
                    "impact": f"Controller cannot detect or generate gaps for unresolved reference '{ent}' in non-IT domains."
                })

    # --------------------------------------------------------------------------
    # 2. AUTHORITY DIVERSITY AUDIT
    # --------------------------------------------------------------------------
    print("\n[TEST SECTION 2] AUTHORITY DIVERSITY AUDIT")
    authority_phrases = [
        ("Board decision: approved", True),
        ("Compliance ruling: approved", True),
        ("Release approval: approved", True),
        ("Regulatory determination: accepted", True),
        ("Operations disposition: approved", True),
        ("Managerial approval: approved", True),
        ("Review committee decision: approved", True),
        ("Signed policy decision: accepted", True),
    ]
    
    retriever = MockRetriever([])
    controller = InvestigationController(retriever=retriever)
    
    for phrase, expected in authority_phrases:
        session = InvestigationSession(session_id="s_auth", objective="Verify governance decision")
        gap = InformationGap(
            gap_id="GAP-AUTH-TEST",
            gap_type=GapType.AUTHORITY_RESOLUTION,
            target_entity="POLICY-17",
            description="Verify authority approval disposition",
            required_information="Approval disposition",
            status=GapStatus.OPEN,
        )
        session.gaps[gap.gap_id] = gap
        ev = make_evidence(
            "EV-AUTH-01",
            f"Governance header: {phrase} for POLICY-17.",
            source_id="RECORD-01"
        )
        session.discovered_evidence[ev.evidence_id] = ev
        
        controller._evaluate_gap_resolution(gap, session, [ev.evidence_id])
        resolved = gap.resolved
        status_str = "RESOLVED" if resolved else "OPEN"
        print(f"  Authority Phrase: {phrase:42} -> Gap Status: {status_str}")
        
        if not resolved:
            findings.append({
                "section": "2. AUTHORITY DIVERSITY",
                "severity": "COUPLING_DEFECT",
                "phrase": phrase,
                "issue": f"Authority phrase '{phrase}' failed to resolve GapType.AUTHORITY_RESOLUTION",
                "location": "backend/investigation/controller.py:_evaluate_gap_resolution / AUTHORITY_DECISION_PATTERN",
                "impact": f"Domain authority record '{phrase}' rejected because regex restricts governance to specific words."
            })

    # --------------------------------------------------------------------------
    # 3. TEMPORAL CONFLICT & ENTITY STATE EXTRACTION AUDIT
    # --------------------------------------------------------------------------
    print("\n[TEST SECTION 3] TEMPORAL CONFLICT & ENTITY EXTRACTION AUDIT ACROSS DOMAINS")
    for domain_name, data in DOMAINS.items():
        ev_old = make_evidence(
            f"EV-{domain_name}-OLD",
            data["contradiction_a"],
            source_id=f"SRC-{domain_name}-OLD",
            created_at="2026-09-01T10:00:00Z"
        )
        ev_new = make_evidence(
            f"EV-{domain_name}-NEW",
            data["contradiction_b"],
            source_id=f"SRC-{domain_name}-NEW",
            created_at="2026-09-02T10:00:00Z"
        )
        
        edges = TemporalConflictScanner.detect_temporal_relationships([ev_old, ev_new])
        edge_types = [e.relationship_type.value for e in edges]
        print(f"  Domain: {domain_name:18} | Extracted Edges: {len(edges)} | Types: {edge_types}")
        
        if len(edges) == 0:
            findings.append({
                "section": "3. TEMPORAL CONFLICT DIVERSITY",
                "severity": "COUPLING_DEFECT",
                "domain": domain_name,
                "issue": f"TemporalConflictScanner detected 0 edges for direct state contradiction in domain '{domain_name}'",
                "location": "backend/investigation/temporal_scanner.py:ENTITY_PATTERN",
                "impact": f"Temporal scanner ENTITY_PATTERN only matches IT/software suffixes (-service, -gateway, etc.), completely blinding the scanner to {domain_name} entities."
            })

    # --------------------------------------------------------------------------
    # 4. GAP RESOLUTION TRANSFER ACROSS 6 DOMAINS
    # --------------------------------------------------------------------------
    print("\n[TEST SECTION 4] GAP RESOLUTION TRANSFER ACROSS 6 DOMAINS")
    for domain_name, data in DOMAINS.items():
        primary_entity = data["entity_ids"][0]
        
        # Test 1: Complete evidence -> RESOLVED
        gap_complete = InformationGap(
            gap_id=f"GAP-{domain_name}-1",
            gap_type=GapType.STATE_VERIFICATION,
            target_entity=primary_entity,
            description=f"Status verification for {primary_entity}",
            required_information=f"Status of {primary_entity}",
            status=GapStatus.OPEN
        )
        sess = InvestigationSession(session_id="s1", objective=f"Verify {primary_entity}")
        sess.gaps[gap_complete.gap_id] = gap_complete
        ev_comp = make_evidence("E-COMP", f"Status: active production verification for {primary_entity}.", source_id=f"SRC-{primary_entity}")
        sess.discovered_evidence[ev_comp.evidence_id] = ev_comp
        controller._evaluate_gap_resolution(gap_complete, sess, [ev_comp.evidence_id])
        res_comp = gap_complete.resolved
        
        # Test 2: Wrong entity -> OPEN
        gap_wrong = InformationGap(
            gap_id=f"GAP-{domain_name}-2",
            gap_type=GapType.STATE_VERIFICATION,
            target_entity=primary_entity,
            description=f"Status verification for {primary_entity}",
            required_information=f"Status of {primary_entity}",
            status=GapStatus.OPEN
        )
        sess2 = InvestigationSession(session_id="s2", objective=f"Verify {primary_entity}")
        sess2.gaps[gap_wrong.gap_id] = gap_wrong
        ev_wrong = make_evidence("E-WRONG", f"Status: active verification for COMPLETELY_DIFFERENT_ENTITY.", source_id="SRC-OTHER")
        sess2.discovered_evidence[ev_wrong.evidence_id] = ev_wrong
        controller._evaluate_gap_resolution(gap_wrong, sess2, [ev_wrong.evidence_id])
        res_wrong = gap_wrong.resolved
        
        # Test 3: Unknown gap type -> OPEN
        gap_unknown = InformationGap(
            gap_id=f"GAP-{domain_name}-3",
            gap_type="CUSTOM_HYPOTHETICAL_TYPE",
            target_entity=primary_entity,
            description=f"Status verification for {primary_entity}",
            required_information=f"Status of {primary_entity}",
            status=GapStatus.OPEN
        )
        sess3 = InvestigationSession(session_id="s3", objective=f"Verify {primary_entity}")
        sess3.gaps[gap_unknown.gap_id] = gap_unknown
        sess3.discovered_evidence[ev_comp.evidence_id] = ev_comp
        controller._evaluate_gap_resolution(gap_unknown, sess3, [ev_comp.evidence_id])
        res_unknown = gap_unknown.resolved
        
        print(f"  Domain: {domain_name:18} | Complete Ev: {res_comp} (Exp: True) | Wrong Entity: {res_wrong} (Exp: False) | Unknown Type: {res_unknown} (Exp: False)")
        
        if not res_comp:
            findings.append({
                "section": "4. GAP RESOLUTION TRANSFER",
                "severity": "COUPLING_DEFECT",
                "domain": domain_name,
                "issue": f"Complete evidence failed to resolve STATE_VERIFICATION gap for entity '{primary_entity}' in domain '{domain_name}'",
                "location": "backend/investigation/controller.py:_evaluate_gap_resolution",
                "impact": "Controller cannot resolve state verification for domain entity."
            })
        if res_wrong:
            findings.append({
                "section": "4. GAP RESOLUTION TRANSFER",
                "severity": "COUPLING_DEFECT",
                "domain": domain_name,
                "issue": f"Wrong entity resolved gap for '{primary_entity}' in domain '{domain_name}'",
                "location": "backend/investigation/controller.py:_evaluate_gap_resolution",
                "impact": "Entity isolation failed."
            })
        if res_unknown:
            findings.append({
                "section": "4. GAP RESOLUTION TRANSFER",
                "severity": "COUPLING_DEFECT",
                "domain": domain_name,
                "issue": f"Unknown gap type resolved by arbitrary evidence in domain '{domain_name}'",
                "location": "backend/investigation/controller.py:_evaluate_gap_resolution",
                "impact": "Premature termination on unrecognized gap."
            })

    # --------------------------------------------------------------------------
    # 5. DOMAIN SUBSTITUTION ATTACK
    # --------------------------------------------------------------------------
    print("\n[TEST SECTION 5] DOMAIN SUBSTITUTION ATTACKS")
    domain_pairs = [
        ("software", "finance"),
        ("finance", "logistics"),
        ("logistics", "manufacturing"),
        ("manufacturing", "healthcare"),
        ("healthcare", "project_planning"),
        ("project_planning", "software"),
    ]
    
    for src_dom, tgt_dom in domain_pairs:
        target_entity = DOMAINS[tgt_dom]["entity_ids"][0]
        ev_item = make_evidence(
            f"SUBST-{src_dom}-{tgt_dom}",
            f"Official status record: {target_entity} is active and verified by governance.",
            source_id=f"SRC-{target_entity}"
        )
        ctrl = InvestigationController(retriever=MockRetriever([ev_item]))
        
        session = InvestigationSession(
            session_id=f"sess_{src_dom}_{tgt_dom}",
            objective=f"Verify current status and compliance for {target_entity}"
        )
        gap = InformationGap(
            gap_id=f"GAP-SUBST-{target_entity}",
            gap_type=GapType.STATE_VERIFICATION,
            target_entity=target_entity,
            description=f"Status verification for {target_entity}",
            required_information=f"Status of {target_entity}",
            status=GapStatus.OPEN
        )
        session.gaps[gap.gap_id] = gap
        session.discovered_evidence[ev_item.evidence_id] = ev_item
        
        ctrl._evaluate_gap_resolution(gap, session, [ev_item.evidence_id])
        print(f"  Substitute {src_dom:16} -> {tgt_dom:16} (Entity: {target_entity:15}): Resolved = {gap.resolved}")

    # --------------------------------------------------------------------------
    # 6. AST & CODEBASE STATIC AUDIT FOR BEHAVIORAL COUPLING
    # --------------------------------------------------------------------------
    print("\n[TEST SECTION 6] AST & CODEBASE STATIC AUDIT")
    target_dirs = ["backend/investigation", "backend/evidence"]
    patterns_to_inspect = {
        "Jira/GitHub source_types": re.compile(r"['\"](?:jira|github)['\"]", re.IGNORECASE),
        "Ticket prefixes": re.compile(r"\b(?:INC|CR|CHG|PR|MR)-\d+\b", re.IGNORECASE),
        "IT entity suffixes": re.compile(r"(?:-service|-gateway|-engine|-cluster|-api|-broker|-db|-app)", re.IGNORECASE),
        "IT lifecycle words": re.compile(r"\b(?:rollback|rolled back|pull request|merge commit)\b", re.IGNORECASE),
    }
    
    for root_dir in target_dirs:
        for root, _, files in os.walk(root_dir):
            for file in files:
                if file.endswith(".py"):
                    filepath = os.path.join(root, file)
                    with open(filepath, "r", encoding="utf-8") as f:
                        code = f.read()
                    
                    for pat_name, pat in patterns_to_inspect.items():
                        matches = pat.findall(code)
                        if matches:
                            print(f"  {filepath:45} | Pattern: {pat_name:25} | Matches: {len(matches)} (e.g. {matches[:3]})")
                            findings.append({
                                "section": "6. AST & STATIC AUDIT",
                                "severity": "ARCHITECTURAL_COUPLING",
                                "file": filepath,
                                "pattern": pat_name,
                                "match_samples": matches[:3],
                                "issue": f"Code contains {pat_name} coupling",
                                "location": filepath,
                                "impact": f"Module encodes domain/infrastructure assumptions instead of pure generic abstractions."
                            })

    # --------------------------------------------------------------------------
    # 7. BEHAVIORAL COUPLING ATTACK VERIFICATION
    # --------------------------------------------------------------------------
    print("\n[TEST SECTION 7] BEHAVIORAL COUPLING ATTACK VERIFICATION")
    # Attack 1: Non-incident / non-CR reference detection
    print("  [Attack 7.1] Testing whether scanner detects references without INC-/CR- prefix...")
    dummy_text = "Referenced financial case CASE-4821 and logistics consignment ORDER-8842."
    extracted_refs = scanner.extract_references(dummy_text)
    print(f"    Extracted references from text: {extracted_refs}")
    if "INCIDENT" not in extracted_refs and "CHANGE_REQUEST" not in extracted_refs and not any(k in extracted_refs for k in ["GENERIC_TICKET", "TICKET"]):
        print("    -> Scanner ignored non-incident/CR ticket references!")
    
    # Attack 2: Unresolved references tracking
    print("  [Attack 7.2] Testing find_unresolved_references on non-IT entity...")
    dummy_ev = make_evidence("E-FIN", "Case requires review of ACCOUNT-77 and CASE-4821.", source_id="DOC-AUDIT")
    unres = scanner.find_unresolved_references({dummy_ev.evidence_id: dummy_ev})
    print(f"    Unresolved references from {dummy_ev.evidence_id}: {unres}")
    if not unres:
        print("    -> find_unresolved_references completely failed to track CASE-4821 and ACCOUNT-77!")
    
    # Attack 3: Deterministic edges without software vocabulary
    print("  [Attack 7.3] Testing deterministic edge contradiction detection on non-IT vocabulary...")
    ev_fin_a = make_evidence("E-FIN-A", "Compliance disposition: rejected credit extension for ACCOUNT-77.", source_id="RECORD-01")
    ev_fin_b = make_evidence("E-FIN-B", "Branch manager requested credit extension for ACCOUNT-77.", source_id="RECORD-02")
    edges_fin = scanner.detect_deterministic_edges([ev_fin_a, ev_fin_b])
    print(f"    Detected edges between opposing financial records: {len(edges_fin)}")
    for e in edges_fin:
        print(f"      Edge: {e.relationship_type.value} | Basis: {e.basis}")
    if not any(e.relationship_type == RelationshipType.CONTRADICTS for e in edges_fin):
        print("    -> Failed to detect CONTRADICTS edge between opposing non-IT records!")

    # --------------------------------------------------------------------------
    # SUMMARY & VERDICT
    # --------------------------------------------------------------------------
    print("\n" + "=" * 80)
    print("ADVERSARIAL DOMAIN TRANSFER VERIFICATION SUMMARY")
    print("=" * 80)
    print(f"Total Coupling / Domain Defects Discovered: {len(findings)}")
    for i, f in enumerate(findings, 1):
        print(f"\nFinding #{i:02d}: [{f['severity']}] in {f['section']}")
        print(f"  Location: {f.get('location', 'N/A')}")
        print(f"  Issue:    {f.get('issue', 'N/A')}")
        print(f"  Impact:   {f.get('impact', 'N/A')}")
        
    verdict = "FAIL" if findings else "PASS"
    print("\n" + "=" * 80)
    print(f"FINAL PHASE 2.2.1 VERDICT: {verdict}")
    print("=" * 80)
    return verdict, findings


if __name__ == "__main__":
    run_tests()
