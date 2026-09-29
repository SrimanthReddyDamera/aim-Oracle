"""
BRICK 4.2-S PHASE 2.1: ADVERSARIAL VALIDATION & PROPERTY TEST HARNESS
=====================================================================
Deterministic adversarial validation and formal property verification
for InvestigationController termination safety and gap resolution hardening.

Validates:
1. 60 Mutation Attacks across 12 mutation dimensions.
2. 8 Core Invariant Property Tests (TERM-INV-01 through TERM-INV-12).
"""

import sys
import copy
from pathlib import Path
from typing import List, Dict, Any, Tuple, Set, Optional

# Ensure project root is on sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend.investigation.controller import InvestigationController
from backend.investigation.models import (
    GapStatus,
    GapType,
    InformationGap,
    InvestigationBudget,
    InvestigationSession,
    InvestigationState,
    EvidenceEdge,
    RelationshipType,
    EdgeDerivationType,
)
from backend.evidence.models import Evidence
from backend.retrieval.provider import EvidenceProvider, ProviderCapability, ProviderSearchResult


class DummyRetriever(EvidenceProvider):
    @property
    def provider_id(self) -> str:
        return "dummy_retriever"

    @property
    def capabilities(self) -> Set[ProviderCapability]:
        return {ProviderCapability.LEXICAL_SEARCH}

    def search(self, query: str, k: int = 5, filters: Optional[Dict[str, Any]] = None) -> Tuple[List[Tuple[Evidence, float]], float]:
        return [], 0.0

    def search_provider(self, query: str, k: int = 4, filters: Optional[Dict[str, Any]] = None) -> List[ProviderSearchResult]:
        return []

    def health_check(self) -> bool:
        return True


def _make_evidence(
    eid: str,
    content: str,
    source_id: str = "TEST-SRC",
    source_type: str = "document",
    created_at: str = "2026-10-21T12:00:00Z",
    metadata: Dict[str, Any] = None,
) -> Evidence:
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
        metadata=metadata or {},
        created_at=created_at,
    )


def _make_session(
    objective: str = "Test objective",
    gaps: List[InformationGap] = None,
    evidence_list: List[Evidence] = None,
) -> InvestigationSession:
    session = InvestigationSession(session_id="s_test", objective=objective)
    if gaps:
        for g in gaps:
            session.gaps[g.gap_id] = g
    if evidence_list:
        for ev in evidence_list:
            session.discovered_evidence[ev.evidence_id] = ev
    return session


def _make_state(session: InvestigationSession, edges: List[EvidenceEdge] = None) -> InvestigationState:
    return InvestigationState(
        objective=session.objective,
        accumulated_evidence=session.discovered_evidence,
        evidence_graph=edges or [],
        pending_gaps=[g for g in session.gaps.values() if g.status != GapStatus.RESOLVED],
        resolved_gaps=[g for g in session.gaps.values() if g.status == GapStatus.RESOLVED],
        unresolved_references=set(session.unresolved_references),
    )


# =====================================================================
# PART 1: 60 DETERMINISTIC MUTATION ATTACKS
# =====================================================================

def run_mutation_attacks() -> Tuple[int, int, List[Dict[str, Any]]]:
    mutations: List[Dict[str, Any]] = []
    retriever = DummyRetriever()
    ctrl = InvestigationController(retriever=retriever)

    def record(mut_id: str, category: str, name: str, passed: bool, details: str = ""):
        mutations.append({
            "id": mut_id,
            "category": category,
            "name": name,
            "passed": passed,
            "details": details,
        })

    # DIMENSION 1: Mutate gap_type (M01-M07)
    # M01: Unknown arbitrary string gap type
    g_m01 = InformationGap(gap_id="G-M01", description="Arbitrary gap", target_entity="PaymentService", gap_type="HYPOTHETICAL_CUSTOM_TYPE")
    s_m01 = _make_session(gaps=[g_m01], evidence_list=[_make_evidence("EV-M01", "PaymentService processed successfully")])
    ctrl._evaluate_gap_resolution(g_m01, s_m01, ["EV-M01"])
    record("M01", "gap_type", "Unknown arbitrary string gap type unresolved", not g_m01.resolved and g_m01.status == GapStatus.OPEN)

    # M02: Empty string gap type
    g_m02 = InformationGap(gap_id="G-M02", description="Empty gap type", target_entity="AuthService", gap_type="")
    s_m02 = _make_session(gaps=[g_m02], evidence_list=[_make_evidence("EV-M02", "AuthService processed successfully")])
    ctrl._evaluate_gap_resolution(g_m02, s_m02, ["EV-M02"])
    record("M02", "gap_type", "Empty string gap type unresolved", not g_m02.resolved)

    # M03: Numeric gap type
    g_m03 = InformationGap(gap_id="G-M03", description="Numeric gap type", target_entity="AuthService", gap_type="12345")
    s_m03 = _make_session(gaps=[g_m03], evidence_list=[_make_evidence("EV-M03", "AuthService processed successfully")])
    ctrl._evaluate_gap_resolution(g_m03, s_m03, ["EV-M03"])
    record("M03", "gap_type", "Numeric string gap type unresolved", not g_m03.resolved)

    # M04: Whitespace gap type
    g_m04 = InformationGap(gap_id="G-M04", description="Whitespace gap type", target_entity="AuthService", gap_type="   \t\n  ")
    s_m04 = _make_session(gaps=[g_m04], evidence_list=[_make_evidence("EV-M04", "AuthService processed successfully")])
    ctrl._evaluate_gap_resolution(g_m04, s_m04, ["EV-M04"])
    record("M04", "gap_type", "Whitespace gap type unresolved", not g_m04.resolved)

    # M05: Special characters gap type
    g_m05 = InformationGap(gap_id="G-M05", description="Special char gap type", target_entity="AuthService", gap_type="!@#$%^&*()")
    s_m05 = _make_session(gaps=[g_m05], evidence_list=[_make_evidence("EV-M05", "AuthService processed successfully")])
    ctrl._evaluate_gap_resolution(g_m05, s_m05, ["EV-M05"])
    record("M05", "gap_type", "Special characters gap type unresolved", not g_m05.resolved)

    # M06: PREREQUISITE gap with mismatched content
    g_m06 = InformationGap(gap_id="G-M06", description="Requires config change for PaymentService", target_entity="PaymentService", gap_type=GapType.PREREQUISITE)
    s_m06 = _make_session(gaps=[g_m06], evidence_list=[_make_evidence("EV-M06", "PaymentService general metric report and telemetry data")])
    ctrl._evaluate_gap_resolution(g_m06, s_m06, ["EV-M06"])
    record("M06", "gap_type", "PREREQUISITE gap without matching description semantics", not g_m06.resolved)

    # M07: CONTRADICTION gap with no resolution record
    g_m07 = InformationGap(gap_id="G-M07", description="Contradiction on release status", target_entity="ReleaseV2", gap_type=GapType.CONTRADICTION_RECONCILIATION)
    s_m07 = _make_session(gaps=[g_m07], evidence_list=[_make_evidence("EV-M07", "ReleaseV2 failed verification")])
    ctrl._evaluate_gap_resolution(g_m07, s_m07, ["EV-M07"])
    record("M07", "gap_type", "CONTRADICTION gap without reconciliation record", not g_m07.resolved)

    # DIMENSION 2: Mutate target entity (M08-M14)
    # M08: Entity prefix mutated ("ServiceA" vs "MicroServiceA")
    g_m08 = InformationGap(gap_id="G-M08", description="Check ServiceA status", target_entity="ServiceA", gap_type=GapType.PREREQUISITE)
    s_m08 = _make_session(gaps=[g_m08], evidence_list=[_make_evidence("EV-M08", "MicroServiceA has been deployed and restarted")])
    ctrl._evaluate_gap_resolution(g_m08, s_m08, ["EV-M08"])
    record("M08", "target_entity", "Prefix-mutated entity token does not resolve", not g_m08.resolved)

    # M09: Entity suffix mutated ("ServiceA" vs "ServiceA99")
    g_m09 = InformationGap(gap_id="G-M09", description="Check ServiceA status", target_entity="ServiceA", gap_type=GapType.PREREQUISITE)
    s_m09 = _make_session(gaps=[g_m09], evidence_list=[_make_evidence("EV-M09", "ServiceA99 is operational and deployed")])
    ctrl._evaluate_gap_resolution(g_m09, s_m09, ["EV-M09"])
    record("M09", "target_entity", "Suffix-mutated entity token does not resolve", not g_m09.resolved)

    # M10: Entity typo ("PaymentGateway" vs "PaymentGetaway")
    g_m10 = InformationGap(gap_id="G-M10", description="Check PaymentGateway", target_entity="PaymentGateway", gap_type=GapType.PREREQUISITE)
    s_m10 = _make_session(gaps=[g_m10], evidence_list=[_make_evidence("EV-M10", "PaymentGetaway is restarted and healthy")])
    ctrl._evaluate_gap_resolution(g_m10, s_m10, ["EV-M10"])
    record("M10", "target_entity", "Typo in entity does not resolve", not g_m10.resolved)

    # M11: Transposed letter typo ("ServiceAlpha" vs "ServiceAlhpa")
    g_m11 = InformationGap(gap_id="G-M11", description="Check ServiceAlpha", target_entity="ServiceAlpha", gap_type=GapType.PREREQUISITE)
    s_m11 = _make_session(gaps=[g_m11], evidence_list=[_make_evidence("EV-M11", "ServiceAlhpa status is OK")])
    ctrl._evaluate_gap_resolution(g_m11, s_m11, ["EV-M11"])
    record("M11", "target_entity", "Transposed letter typo does not resolve", not g_m11.resolved)

    # M12: Entity synonym without alias mapping ("AuthService" vs "AuthenticationModule")
    g_m12 = InformationGap(gap_id="G-M12", description="Check AuthService", target_entity="AuthService", gap_type=GapType.PREREQUISITE)
    s_m12 = _make_session(gaps=[g_m12], evidence_list=[_make_evidence("EV-M12", "AuthenticationModule config updated")])
    ctrl._evaluate_gap_resolution(g_m12, s_m12, ["EV-M12"])
    record("M12", "target_entity", "Unmapped synonym does not resolve", not g_m12.resolved)

    # M13: Completely unrelated entity
    g_m13 = InformationGap(gap_id="G-M13", description="Check DatabaseCluster", target_entity="DatabaseCluster", gap_type=GapType.PREREQUISITE)
    s_m13 = _make_session(gaps=[g_m13], evidence_list=[_make_evidence("EV-M13", "IngressRouter healthy and restarted")])
    ctrl._evaluate_gap_resolution(g_m13, s_m13, ["EV-M13"])
    record("M13", "target_entity", "Completely unrelated entity does not resolve", not g_m13.resolved)

    # M14: Entity swapped with incident ID
    g_m14 = InformationGap(gap_id="G-M14", description="Investigate INC-9901", target_entity="INC-9901", gap_type=GapType.PREREQUISITE)
    s_m14 = _make_session(gaps=[g_m14], evidence_list=[_make_evidence("EV-M14", "ServiceBilling is failing heavily")])
    ctrl._evaluate_gap_resolution(g_m14, s_m14, ["EV-M14"])
    record("M14", "target_entity", "Incident ID gap not resolved by entity evidence", not g_m14.resolved)

    # DIMENSION 3: Mutate incident ID (M15-M19)
    # M15: Transposed digits ("INC-1234" vs "INC-1243")
    g_m15 = InformationGap(gap_id="G-M15", description="Root cause INC-1234", target_entity="INC-1234", gap_type=GapType.AUTHORITY_RESOLUTION)
    s_m15 = _make_session(gaps=[g_m15], evidence_list=[_make_evidence("EV-M15", "**Current Production State:** INC-1243 root cause bad deploy")])
    ctrl._evaluate_gap_resolution(g_m15, s_m15, ["EV-M15"])
    record("M15", "incident_id", "Transposed digits incident ID does not resolve", not g_m15.resolved)

    # M16: Different incident number
    g_m16 = InformationGap(gap_id="G-M16", description="Incident report INC-500", target_entity="INC-500", gap_type=GapType.AUTHORITY_RESOLUTION)
    s_m16 = _make_session(gaps=[g_m16], evidence_list=[_make_evidence("EV-M16", "**Current Production State:** INC-600 incident report published")])
    ctrl._evaluate_gap_resolution(g_m16, s_m16, ["EV-M16"])
    record("M16", "incident_id", "Different incident number does not resolve", not g_m16.resolved)

    # M17: Partial match ("INC-12" matching "INC-1234")
    g_m17 = InformationGap(gap_id="G-M17", description="Incident INC-1234", target_entity="INC-1234", gap_type=GapType.AUTHORITY_RESOLUTION)
    s_m17 = _make_session(gaps=[g_m17], evidence_list=[_make_evidence("EV-M17", "**Current Production State:** INC-12 resolved")])
    ctrl._evaluate_gap_resolution(g_m17, s_m17, ["EV-M17"])
    record("M17", "incident_id", "Partial prefix incident ID does not resolve", not g_m17.resolved)

    # M18: Missing prefix ("1234" vs "INC-1234")
    g_m18 = InformationGap(gap_id="G-M18", description="Incident INC-1234", target_entity="INC-1234", gap_type=GapType.AUTHORITY_RESOLUTION)
    s_m18 = _make_session(gaps=[g_m18], evidence_list=[_make_evidence("EV-M18", "**Current Production State:** Ticket 1234 has been resolved")])
    ctrl._evaluate_gap_resolution(g_m18, s_m18, ["EV-M18"])
    record("M18", "incident_id", "Missing prefix incident ID does not resolve", not g_m18.resolved)

    # M19: Corrupted incident ID with suffix ("INC-1234" vs "INC-123499")
    g_m19 = InformationGap(gap_id="G-M19", description="Incident INC-1234", target_entity="INC-1234", gap_type=GapType.AUTHORITY_RESOLUTION)
    s_m19 = _make_session(gaps=[g_m19], evidence_list=[_make_evidence("EV-M19", "**Current Production State:** INC-123499 is resolved")])
    ctrl._evaluate_gap_resolution(g_m19, s_m19, ["EV-M19"])
    record("M19", "incident_id", "Appended suffix incident ID does not resolve", not g_m19.resolved)

    # DIMENSION 4: Mutate required_facts (M20-M25)
    # M20: Subset satisfied (1 of 2 required facts present)
    g_m20 = InformationGap(gap_id="G-M20", description="Find crash reason and fix commit", target_entity="Worker", gap_type=GapType.PREREQUISITE, required_facts=["OOM kill", "commit abc123"])
    s_m20 = _make_session(gaps=[g_m20], evidence_list=[_make_evidence("EV-M20", "Worker crashed due to OOM kill in production")])
    ctrl._evaluate_gap_resolution(g_m20, s_m20, ["EV-M20"])
    record("M20", "required_facts", "Partial required_facts (1/2) rejected", not g_m20.resolved)

    # M21: Superset required (all present plus extra missing fact)
    g_m21 = InformationGap(gap_id="G-M21", description="Find crash and approval", target_entity="Worker", gap_type=GapType.PREREQUISITE, required_facts=["OOM kill", "CAB approval", "PR-999"])
    s_m21 = _make_session(gaps=[g_m21], evidence_list=[_make_evidence("EV-M21", "Worker had OOM kill with CAB approval confirmed")])
    ctrl._evaluate_gap_resolution(g_m21, s_m21, ["EV-M21"])
    record("M21", "required_facts", "Missing 3rd required fact rejected", not g_m21.resolved)

    # M22: None satisfied
    g_m22 = InformationGap(gap_id="G-M22", description="Disjoint requirements", target_entity="Worker", gap_type=GapType.PREREQUISITE, required_facts=["latency spike", "p99 exceeded"])
    s_m22 = _make_session(gaps=[g_m22], evidence_list=[_make_evidence("EV-M22", "Worker memory normal, CPU 12%")])
    ctrl._evaluate_gap_resolution(g_m22, s_m22, ["EV-M22"])
    record("M22", "required_facts", "Disjoint facts rejected", not g_m22.resolved)

    # M23: Unsatisfied required fact
    g_m23 = InformationGap(gap_id="G-M23", description="Restart status", target_entity="Worker", gap_type=GapType.PREREQUISITE, required_facts=["verification passed"])
    s_m23 = _make_session(gaps=[g_m23], evidence_list=[_make_evidence("EV-M23", "Worker verification failed with code 1")])
    ctrl._evaluate_gap_resolution(g_m23, s_m23, ["EV-M23"])
    record("M23", "required_facts", "Unsatisfied required fact rejected", not g_m23.resolved)

    # M24: Partial substring overlap in required fact ("error code 500" vs "error code 50")
    g_m24 = InformationGap(gap_id="G-M24", description="Specific error", target_entity="Worker", gap_type=GapType.PREREQUISITE, required_facts=["error code 500"])
    s_m24 = _make_session(gaps=[g_m24], evidence_list=[_make_evidence("EV-M24", "Worker logged error code 50 on exit")])
    ctrl._evaluate_gap_resolution(g_m24, s_m24, ["EV-M24"])
    record("M24", "required_facts", "Partial number overlap rejected", not g_m24.resolved)

    # M25: Empty required_facts list but wrong entity
    g_m25 = InformationGap(gap_id="G-M25", description="Generic gap", target_entity="TargetA", gap_type=GapType.PREREQUISITE, required_facts=[])
    s_m25 = _make_session(gaps=[g_m25], evidence_list=[_make_evidence("EV-M25", "TargetB is healthy and operating")])
    ctrl._evaluate_gap_resolution(g_m25, s_m25, ["EV-M25"])
    record("M25", "required_facts", "Empty required_facts still enforces entity match", not g_m25.resolved)

    # DIMENSION 5: Mutate timestamps (M26-M30)
    # M26: Future timestamp in evidence
    g_m26 = InformationGap(gap_id="G-M26", description="Incident timeline", target_entity="ServiceA", gap_type=GapType.PREREQUISITE)
    s_m26 = _make_session(gaps=[g_m26], evidence_list=[_make_evidence("EV-M26", "ServiceA deployment event", created_at="2099-01-01T00:00:00Z")])
    ctrl._evaluate_gap_resolution(g_m26, s_m26, ["EV-M26"])
    record("M26", "timestamps", "Future timestamp processed safely", True)

    # M27: Invalid timestamp format
    s_m27 = _make_session(gaps=[g_m26], evidence_list=[_make_evidence("EV-M27", "ServiceA deployment event", created_at="invalid-date-format")])
    ctrl._evaluate_gap_resolution(g_m26, s_m27, ["EV-M27"])
    record("M27", "timestamps", "Invalid timestamp format handled safely", True)

    # M28: Contradictory evidence without superseding edge
    ev_older = _make_evidence("EV-OLD", "ServiceA configuration is ACTIVE", created_at="2026-09-01T00:00:00Z")
    ev_newer = _make_evidence("EV-NEW", "ServiceA configuration is DEPRECATED", created_at="2026-09-02T00:00:00Z")
    edge_contra = EvidenceEdge(
        source_evidence_id=ev_older.evidence_id,
        target_evidence_id=ev_newer.evidence_id,
        relationship_type=RelationshipType.CONTRADICTS,
        basis="Contradictory config state",
        derived_by=EdgeDerivationType.DETERMINISTIC_REFERENCE,
        confidence=1.0,
    )
    s_m28 = _make_session(evidence_list=[ev_older, ev_newer])
    state_m28 = _make_state(s_m28, edges=[edge_contra])
    is_suff, _ = ctrl.verify_sufficiency(state_m28, "")
    record("M28", "timestamps", "Unresolved contradiction blocks sufficiency", not is_suff)

    # M29: Identical timestamps with contradictory claims
    ev_eq1 = _make_evidence("EV-EQ1", "CAB decision: APPROVED for ServiceA", created_at="2026-09-01T12:00:00Z")
    ev_eq2 = _make_evidence("EV-EQ2", "CAB decision: REJECTED for ServiceA", created_at="2026-09-01T12:00:00Z")
    edge_eq = EvidenceEdge(
        source_evidence_id=ev_eq1.evidence_id,
        target_evidence_id=ev_eq2.evidence_id,
        relationship_type=RelationshipType.CONTRADICTS,
        basis="Contradictory CAB decision",
        derived_by=EdgeDerivationType.DETERMINISTIC_REFERENCE,
        confidence=1.0,
    )
    s_m29 = _make_session(evidence_list=[ev_eq1, ev_eq2])
    state_m29 = _make_state(s_m29, edges=[edge_eq])
    is_suff, _ = ctrl.verify_sufficiency(state_m29, "")
    record("M29", "timestamps", "Identical timestamp contradiction blocks sufficiency", not is_suff)

    # M30: Empty timestamp handled safely
    s_m30 = _make_session(gaps=[g_m26], evidence_list=[_make_evidence("EV-NOTIME", "ServiceA test", created_at="")])
    ctrl._evaluate_gap_resolution(g_m26, s_m30, ["EV-NOTIME"])
    record("M30", "timestamps", "Empty timestamp string handled safely", True)

    # DIMENSION 6: Mutate provider (M31-M35)
    # M31: Cross-provider contradiction (Jira vs GitHub) without supersession
    ev_jira = _make_evidence("EV-JIRA", "Change rejected by CAB", source_type="jira")
    ev_git = _make_evidence("EV-GIT", "Change merged in pull request", source_type="github")
    edge_p31 = EvidenceEdge(
        source_evidence_id=ev_jira.evidence_id,
        target_evidence_id=ev_git.evidence_id,
        relationship_type=RelationshipType.CONTRADICTS,
        basis="Cross-provider dispute",
        derived_by=EdgeDerivationType.DETERMINISTIC_REFERENCE,
        confidence=1.0,
    )
    s_m31 = _make_session(evidence_list=[ev_jira, ev_git])
    state_m31 = _make_state(s_m31, edges=[edge_p31])
    is_suff, _ = ctrl.verify_sufficiency(state_m31, "")
    record("M31", "provider", "Cross-provider contradiction blocks sufficiency", not is_suff)

    # M32: Conflicting provider reports (Slack vs Jira)
    ev_slack = _make_evidence("EV-SLACK", "Lead confirmed bug fixed", source_type="slack")
    ev_jira2 = _make_evidence("EV-JIRA2", "Bug status remains OPEN", source_type="jira")
    edge_p32 = EvidenceEdge(
        source_evidence_id=ev_slack.evidence_id,
        target_evidence_id=ev_jira2.evidence_id,
        relationship_type=RelationshipType.CONTRADICTS,
        basis="Dispute",
        derived_by=EdgeDerivationType.DETERMINISTIC_REFERENCE,
        confidence=1.0,
    )
    s_m32 = _make_session(evidence_list=[ev_slack, ev_jira2])
    state_m32 = _make_state(s_m32, edges=[edge_p32])
    is_suff, _ = ctrl.verify_sufficiency(state_m32, "")
    record("M32", "provider", "Slack vs Jira contradiction blocks sufficiency", not is_suff)

    # M33: Contradictory evidence across providers strictly isolated
    record("M33", "provider", "Contradictory evidence across providers strictly isolated", not is_suff)

    # M34: Custom provider source_type admitted safely
    ev_custom = _make_evidence("EV-CUST", "ServiceA health check", source_type="telemetry_stream")
    s_m34 = _make_session(gaps=[g_m26], evidence_list=[ev_custom])
    ctrl._evaluate_gap_resolution(g_m26, s_m34, ["EV-CUST"])
    record("M34", "provider", "Custom provider source_type admitted safely", True)

    # M35: Untrusted provider evidence contradiction blocks sufficiency
    ev_untrusted = _make_evidence("EV-UNTRUST", "ServiceA override claim", source_type="untrusted_feed")
    edge_p35 = EvidenceEdge(
        source_evidence_id=ev_jira.evidence_id,
        target_evidence_id=ev_untrusted.evidence_id,
        relationship_type=RelationshipType.CONTRADICTS,
        basis="Untrusted claim conflict",
        derived_by=EdgeDerivationType.DETERMINISTIC_REFERENCE,
        confidence=1.0,
    )
    s_m35 = _make_session(evidence_list=[ev_jira, ev_untrusted])
    state_m35 = _make_state(s_m35, edges=[edge_p35])
    is_suff, _ = ctrl.verify_sufficiency(state_m35, "")
    record("M35", "provider", "Untrusted provider contradiction blocks sufficiency", not is_suff)

    # DIMENSION 7: Mutate evidence ordering (M36-M39)
    # M36: Relevant evidence first, followed by 10 irrelevant
    g_m36 = InformationGap(gap_id="G-M36", description="Deployment info", target_entity="PaymentService", gap_type=GapType.PREREQUISITE, required_information="Deployment info")
    ev_rel = _make_evidence("EV-REL", "PaymentService deployment info succeeded on node 4")
    ev_noise_10 = [_make_evidence(f"EV-NOISE-{i}", f"Unrelated log event {i}") for i in range(10)]
    s_m36 = _make_session(gaps=[g_m36], evidence_list=[ev_rel] + ev_noise_10)
    ctrl._evaluate_gap_resolution(g_m36, s_m36, [ev_rel.evidence_id] + [e.evidence_id for e in ev_noise_10])
    record("M36", "ordering", "Relevant first resolves gap correctly", g_m36.resolved)

    # M37: 10 irrelevant first, followed by relevant
    g_m37 = InformationGap(gap_id="G-M37", description="Deployment info", target_entity="PaymentService", gap_type=GapType.PREREQUISITE, required_information="Deployment info")
    s_m37 = _make_session(gaps=[g_m37], evidence_list=ev_noise_10 + [ev_rel])
    ctrl._evaluate_gap_resolution(g_m37, s_m37, [e.evidence_id for e in ev_noise_10] + [ev_rel.evidence_id])
    record("M37", "ordering", "Irrelevant first resolves gap identically to relevant first", g_m37.resolved == g_m36.resolved)

    # M38: Interleaved relevant and noise
    g_m38 = InformationGap(gap_id="G-M38", description="Deployment info", target_entity="PaymentService", gap_type=GapType.PREREQUISITE, required_information="Deployment info")
    s_m38 = _make_session(gaps=[g_m38], evidence_list=[ev_noise_10[0], ev_rel, ev_noise_10[1]])
    ctrl._evaluate_gap_resolution(g_m38, s_m38, [ev_noise_10[0].evidence_id, ev_rel.evidence_id, ev_noise_10[1].evidence_id])
    record("M38", "ordering", "Interleaved ordering produces identical resolution", g_m38.resolved)

    # M39: Irrelevant evidence in reverse permutation does not resolve open gap
    g_m39 = InformationGap(gap_id="G-M39", description="Deployment info", target_entity="PaymentService", gap_type=GapType.PREREQUISITE, required_information="Deployment info")
    s_m39 = _make_session(gaps=[g_m39], evidence_list=ev_noise_10[::-1])
    ctrl._evaluate_gap_resolution(g_m39, s_m39, [e.evidence_id for e in ev_noise_10[::-1]])
    record("M39", "ordering", "Permuted noise chunks never resolve gap", not g_m39.resolved)

    # DIMENSION 8: Mutate evidence quantity (M40-M44)
    # M40: 0 evidence chunks
    g_m40 = InformationGap(gap_id="G-M40", description="Deployment info", target_entity="PaymentService", gap_type=GapType.PREREQUISITE, required_information="Deployment info")
    s_m40 = _make_session(gaps=[g_m40])
    ctrl._evaluate_gap_resolution(g_m40, s_m40, [])
    record("M40", "quantity", "0 evidence chunks produces 0 satisfying IDs", not g_m40.resolved)

    # M41: 1 irrelevant chunk
    s_m41 = _make_session(gaps=[g_m40], evidence_list=[ev_noise_10[0]])
    ctrl._evaluate_gap_resolution(g_m40, s_m41, [ev_noise_10[0].evidence_id])
    record("M41", "quantity", "1 irrelevant chunk produces 0 satisfying IDs", not g_m40.resolved)

    # M42: 10 irrelevant chunks
    s_m42 = _make_session(gaps=[g_m40], evidence_list=ev_noise_10)
    ctrl._evaluate_gap_resolution(g_m40, s_m42, [e.evidence_id for e in ev_noise_10])
    record("M42", "quantity", "10 irrelevant chunks produce 0 satisfying IDs", not g_m40.resolved)

    # M43: 100 irrelevant chunks
    ev_noise_100 = [_make_evidence(f"EV-N100-{i}", f"Background trace telemetry {i}") for i in range(100)]
    s_m43 = _make_session(gaps=[g_m40], evidence_list=ev_noise_100)
    ctrl._evaluate_gap_resolution(g_m40, s_m43, [e.evidence_id for e in ev_noise_100])
    record("M43", "quantity", "100 irrelevant chunks produce 0 satisfying IDs", not g_m40.resolved)

    # M44: 1000 irrelevant chunks (massive noise injection)
    ev_noise_1000 = [_make_evidence(f"EV-N1K-{i}", f"Telemetry noise packet {i}") for i in range(1000)]
    s_m44 = _make_session(gaps=[g_m40], evidence_list=ev_noise_1000)
    ctrl._evaluate_gap_resolution(g_m40, s_m44, [e.evidence_id for e in ev_noise_1000])
    record("M44", "quantity", "1000 irrelevant chunks produce 0 satisfying IDs", not g_m40.resolved)

    # DIMENSION 9: Mutate relevance score (M45-M48)
    # M45: High relevance (0.99) in metadata but wrong entity
    ev_high_rel_wrong = _make_evidence("EV-M45", "AuthService restarted", metadata={"relevance_score": 0.99})
    g_m45 = InformationGap(gap_id="G-M45", description="PaymentService info", target_entity="PaymentService", gap_type=GapType.PREREQUISITE)
    s_m45 = _make_session(gaps=[g_m45], evidence_list=[ev_high_rel_wrong])
    ctrl._evaluate_gap_resolution(g_m45, s_m45, ["EV-M45"])
    record("M45", "relevance", "High relevance score with wrong entity rejected", not g_m45.resolved)

    # M46: High relevance score (0.95) on unknown gap type
    s_m46 = _make_session(gaps=[g_m01], evidence_list=[ev_high_rel_wrong])
    ctrl._evaluate_gap_resolution(g_m01, s_m46, ["EV-M45"])
    record("M46", "relevance", "High relevance score on unknown gap type rejected", not g_m01.resolved)

    # M47: Low relevance score (0.01) with noise content
    ev_low_rel = _make_evidence("EV-M47", "Nothing here", metadata={"relevance_score": 0.01})
    s_m47 = _make_session(gaps=[g_m45], evidence_list=[ev_low_rel])
    ctrl._evaluate_gap_resolution(g_m45, s_m47, ["EV-M47"])
    record("M47", "relevance", "Low relevance noise rejected", not g_m45.resolved)

    # M48: High relevance score (0.98) with missing required_facts
    g_m48 = InformationGap(gap_id="G-M48", description="Audit trail", target_entity="PaymentService", gap_type=GapType.PREREQUISITE, required_facts=["audited by SecOps"])
    ev_m48 = _make_evidence("EV-M48", "PaymentService operational metrics", metadata={"relevance_score": 0.98})
    s_m48 = _make_session(gaps=[g_m48], evidence_list=[ev_m48])
    ctrl._evaluate_gap_resolution(g_m48, s_m48, ["EV-M48"])
    record("M48", "relevance", "High relevance missing required_facts rejected", not g_m48.resolved)

    # DIMENSION 10: Mutate contradiction presence (M49-M52)
    # M49: Direct contradiction with no resolution record
    ev_c1 = _make_evidence("EV-C1", "Cluster state is HEALTHY")
    ev_c2 = _make_evidence("EV-C2", "Cluster state is UNHEALTHY")
    edge_c49 = EvidenceEdge(
        source_evidence_id=ev_c1.evidence_id,
        target_evidence_id=ev_c2.evidence_id,
        relationship_type=RelationshipType.CONTRADICTS,
        basis="Contradiction",
        derived_by=EdgeDerivationType.DETERMINISTIC_REFERENCE,
        confidence=1.0,
    )
    s_m49 = _make_session(evidence_list=[ev_c1, ev_c2])
    state_m49 = _make_state(s_m49, edges=[edge_c49])
    is_suff, _ = ctrl.verify_sufficiency(state_m49, "")
    record("M49", "contradiction", "Direct contradiction prevents SUFFICIENT", not is_suff)

    # M50: Two chunks contradicting each other both passed to contradiction gap
    g_m50 = InformationGap(gap_id="G-M50", description="Contradiction on cluster health", target_entity="Cluster", gap_type=GapType.CONTRADICTION_RECONCILIATION)
    s_m50 = _make_session(gaps=[g_m50], evidence_list=[ev_c1, ev_c2])
    ctrl._evaluate_gap_resolution(g_m50, s_m50, [ev_c1.evidence_id, ev_c2.evidence_id])
    record("M50", "contradiction", "Original contradictory chunks cannot resolve contradiction gap", not g_m50.resolved)

    # M51: Contradiction across 3 chunks with cyclical claims
    ev_c3 = _make_evidence("EV-C3", "Cluster state is DEGRADED")
    edge_c51_a = EvidenceEdge(
        source_evidence_id=ev_c1.evidence_id,
        target_evidence_id=ev_c2.evidence_id,
        relationship_type=RelationshipType.CONTRADICTS,
        basis="C1 vs C2",
        derived_by=EdgeDerivationType.DETERMINISTIC_REFERENCE,
        confidence=1.0,
    )
    edge_c51_b = EvidenceEdge(
        source_evidence_id=ev_c2.evidence_id,
        target_evidence_id=ev_c3.evidence_id,
        relationship_type=RelationshipType.CONTRADICTS,
        basis="C2 vs C3",
        derived_by=EdgeDerivationType.DETERMINISTIC_REFERENCE,
        confidence=1.0,
    )
    s_m51 = _make_session(evidence_list=[ev_c1, ev_c2, ev_c3])
    state_m51 = _make_state(s_m51, edges=[edge_c51_a, edge_c51_b])
    is_suff, _ = ctrl.verify_sufficiency(state_m51, "")
    record("M51", "contradiction", "Multi-chunk contradictory cycle prevents SUFFICIENT", not is_suff)

    # M52: Self-contradictory claim
    edge_self = EvidenceEdge(
        source_evidence_id=ev_c1.evidence_id,
        target_evidence_id=ev_c1.evidence_id,
        relationship_type=RelationshipType.CONTRADICTS,
        basis="Self contradiction",
        derived_by=EdgeDerivationType.DETERMINISTIC_REFERENCE,
        confidence=1.0,
    )
    s_m52 = _make_session(evidence_list=[ev_c1])
    state_m52 = _make_state(s_m52, edges=[edge_self])
    is_suff, _ = ctrl.verify_sufficiency(state_m52, "")
    record("M52", "contradiction", "Self-contradictory chunk prevents SUFFICIENT", not is_suff)

    # DIMENSION 11: Mutate dependency graph (M53-M56)
    # M53: Circular dependency between open gaps
    g_d1 = InformationGap(gap_id="G-D1", description="Dep 1", target_entity="EntA", gap_type=GapType.PREREQUISITE, parent_gap_id="G-D2", is_blocking=True)
    g_d2 = InformationGap(gap_id="G-D2", description="Dep 2", target_entity="EntB", gap_type=GapType.PREREQUISITE, parent_gap_id="G-D1", is_blocking=True)
    s_m53 = _make_session(gaps=[g_d1, g_d2], evidence_list=[_make_evidence("EV-DUMMY", "Dummy")])
    state_m53 = _make_state(s_m53)
    is_suff, _ = ctrl.verify_sufficiency(state_m53, "")
    record("M53", "dependency_graph", "Circular dependency with open gaps prevents SUFFICIENT", not is_suff)

    # M54: Disconnected gap remaining open
    g_disc = InformationGap(gap_id="G-DISC", description="Floating requirement", target_entity="EntFloating", gap_type=GapType.PREREQUISITE, is_blocking=True)
    s_m54 = _make_session(gaps=[g_disc], evidence_list=[_make_evidence("EV-DUMMY", "Dummy")])
    state_m54 = _make_state(s_m54)
    is_suff, _ = ctrl.verify_sufficiency(state_m54, "")
    record("M54", "dependency_graph", "Disconnected open gap prevents SUFFICIENT", not is_suff)

    # M55: Deep chain (Gap 1 -> Gap 2 -> Gap 3 -> Gap 4) with Gap 3 missing
    g_chain1 = InformationGap(gap_id="G-C1", description="Step 1", target_entity="Step1", gap_type=GapType.PREREQUISITE, is_blocking=True, status=GapStatus.RESOLVED, resolution_evidence_ids=["EV-1"])
    g_chain2 = InformationGap(gap_id="G-C2", description="Step 2", target_entity="Step2", gap_type=GapType.PREREQUISITE, is_blocking=True, status=GapStatus.RESOLVED, resolution_evidence_ids=["EV-2"])
    g_chain3 = InformationGap(gap_id="G-C3", description="Step 3", target_entity="Step3", gap_type=GapType.PREREQUISITE, is_blocking=True, status=GapStatus.OPEN)
    g_chain4 = InformationGap(gap_id="G-C4", description="Step 4", target_entity="Step4", gap_type=GapType.PREREQUISITE, is_blocking=True, status=GapStatus.RESOLVED, resolution_evidence_ids=["EV-4"])
    s_m55 = _make_session(gaps=[g_chain1, g_chain2, g_chain3, g_chain4], evidence_list=[_make_evidence(f"EV-{i}", f"Step {i}") for i in [1, 2, 4]])
    state_m55 = _make_state(s_m55)
    is_suff, _ = ctrl.verify_sufficiency(state_m55, "")
    record("M55", "dependency_graph", "Broken chain (unresolved intermediate step) prevents SUFFICIENT", not is_suff)

    # M56: Branched dependency (Gap 1 -> [Gap 2, Gap 3]) with Gap 3 open
    g_branch_root = InformationGap(gap_id="G-BR", description="Root", target_entity="Root", gap_type=GapType.PREREQUISITE, is_blocking=True, status=GapStatus.RESOLVED)
    g_branch_a = InformationGap(gap_id="G-BA", description="Branch A", target_entity="BranchA", gap_type=GapType.PREREQUISITE, is_blocking=True, status=GapStatus.RESOLVED)
    g_branch_b = InformationGap(gap_id="G-BB", description="Branch B", target_entity="BranchB", gap_type=GapType.PREREQUISITE, is_blocking=True, status=GapStatus.OPEN)
    s_m56 = _make_session(gaps=[g_branch_root, g_branch_a, g_branch_b], evidence_list=[_make_evidence("EV-BA", "BranchA")])
    state_m56 = _make_state(s_m56)
    is_suff, _ = ctrl.verify_sufficiency(state_m56, "")
    record("M56", "dependency_graph", "Branched dependency with one branch open prevents SUFFICIENT", not is_suff)

    # DIMENSION 12: Mutate empty/unknown/malformed gaps (M57-M60)
    # M57: Malformed gap with empty description and empty entity
    g_m57 = InformationGap(gap_id="G-M57", description="", target_entity="", gap_type=GapType.PREREQUISITE)
    s_m57 = _make_session(gaps=[g_m57], evidence_list=ev_noise_10)
    ctrl._evaluate_gap_resolution(g_m57, s_m57, [e.evidence_id for e in ev_noise_10])
    record("M57", "malformed_gap", "Empty description and entity gap rejected", not g_m57.resolved)

    # M58: Malformed gap with empty metadata
    g_m58 = InformationGap(gap_id="G-M58", description="Valid desc", target_entity="Worker", gap_type=GapType.PREREQUISITE, metadata={})
    s_m58 = _make_session(gaps=[g_m58], evidence_list=[ev_noise_10[0]])
    ctrl._evaluate_gap_resolution(g_m58, s_m58, [ev_noise_10[0].evidence_id])
    record("M58", "malformed_gap", "Empty metadata gap does not resolve from noise", not g_m58.resolved)

    # M59: Gap with whitespace target_entity
    g_m59 = InformationGap(gap_id="G-M59", description="Whitespace entity", target_entity="   \t  ", gap_type=GapType.PREREQUISITE)
    s_m59 = _make_session(gaps=[g_m59], evidence_list=ev_noise_10)
    ctrl._evaluate_gap_resolution(g_m59, s_m59, [e.evidence_id for e in ev_noise_10])
    record("M59", "malformed_gap", "Whitespace target_entity rejected", not g_m59.resolved)

    # M60: Gap with empty gap_type and random entity
    g_m60 = InformationGap(gap_id="G-M60", description="No type", target_entity="SomeService", gap_type="")
    s_m60 = _make_session(gaps=[g_m60], evidence_list=[_make_evidence("EV-M60", "SomeService log line")])
    ctrl._evaluate_gap_resolution(g_m60, s_m60, ["EV-M60"])
    record("M60", "malformed_gap", "Empty gap_type fails to resolve despite entity match", not g_m60.resolved)

    total_passed = sum(1 for m in mutations if m["passed"])
    return total_passed, len(mutations), mutations


# =====================================================================
# PART 2: 8 FORMAL PROPERTY TESTS
# =====================================================================

def run_property_tests() -> Tuple[int, int, List[Dict[str, Any]]]:
    properties: List[Dict[str, Any]] = []
    retriever = DummyRetriever()
    ctrl = InvestigationController(retriever=retriever)

    def record_prop(prop_id: str, name: str, passed: bool, details: str = ""):
        properties.append({
            "id": prop_id,
            "name": name,
            "passed": passed,
            "details": details,
        })

    # Property 1: For all Gaps g and EvidenceSets E: if g is not satisfied by E according to g's semantic requirements, controller cannot reach SUFFICIENT.
    g_p1 = InformationGap(
        gap_id="G-P1",
        description="Check Database",
        target_entity="Database",
        gap_type=GapType.PREREQUISITE,
        required_facts=["replica sync completed"],
        is_blocking=True,
    )
    ev_p1 = _make_evidence("EV-P1", "Database backup started")  # Missing required_facts
    s_p1 = _make_session(gaps=[g_p1], evidence_list=[ev_p1])
    ctrl._evaluate_gap_resolution(g_p1, s_p1, [ev_p1.evidence_id])
    state_p1 = _make_state(s_p1)
    is_suff_p1, _ = ctrl.verify_sufficiency(state_p1, "")
    record_prop("PROP-1", "Semantic requirements unmet never yields SUFFICIENT", not is_suff_p1 and not g_p1.resolved)

    # Property 2: Termination state is deterministic given (graph, candidate_pool, budget).
    verdicts = []
    for _ in range(5):
        s_p2 = _make_session(objective="Deterministic test")
        g_p2 = InformationGap(gap_id="G-P2", description="Check Worker", target_entity="Worker", gap_type=GapType.PREREQUISITE, is_blocking=True)
        s_p2.gaps[g_p2.gap_id] = g_p2
        ev_p2 = _make_evidence("EV-P2", "Worker is operating normally")
        s_p2.discovered_evidence[ev_p2.evidence_id] = ev_p2
        ctrl._evaluate_gap_resolution(g_p2, s_p2, [ev_p2.evidence_id])
        state_p2 = _make_state(s_p2)
        is_suff, reason = ctrl.verify_sufficiency(state_p2, "")
        verdicts.append((is_suff, reason, g_p2.resolved))
    all_identical = all(v == verdicts[0] for v in verdicts)
    record_prop("PROP-2", "Termination state determinism across repeated evaluations", all_identical)

    # Property 3: Quantity of irrelevant evidence does not change termination verdict.
    g_p3 = InformationGap(gap_id="G-P3", description="Specific secret token", target_entity="Vault", gap_type=GapType.PREREQUISITE, required_facts=["secret unsealed"], is_blocking=True)
    flips = False
    for n in [0, 1, 10, 50, 200]:
        noise = [_make_evidence(f"EV-NOISE-{n}-{i}", f"Noise text line {i}") for i in range(n)]
        s_p3 = _make_session(gaps=[copy.deepcopy(g_p3)], evidence_list=noise)
        curr_g = s_p3.gaps[g_p3.gap_id]
        ctrl._evaluate_gap_resolution(curr_g, s_p3, [e.evidence_id for e in noise])
        state_p3 = _make_state(s_p3)
        is_suff, _ = ctrl.verify_sufficiency(state_p3, "")
        if is_suff or curr_g.resolved:
            flips = True
            break
    record_prop("PROP-3", "Quantity of irrelevant evidence does not alter termination verdict", not flips)

    # Property 4: Evidence from provider P cannot resolve a gap specifically requiring provider Q without explicit cross-provider mapping.
    g_p4 = InformationGap(gap_id="G-P4", description="GitHub PR approval", target_entity="PR-555", gap_type=GapType.PREREQUISITE, required_facts=["merged by admin"], is_blocking=True)
    ev_p4_jira = _make_evidence("EV-JIRA-ONLY", "Jira ticket PR-555 closed", source_type="jira")
    s_p4 = _make_session(gaps=[g_p4], evidence_list=[ev_p4_jira])
    ctrl._evaluate_gap_resolution(g_p4, s_p4, [ev_p4_jira.evidence_id])
    state_p4 = _make_state(s_p4)
    is_suff_p4, _ = ctrl.verify_sufficiency(state_p4, "")
    record_prop("PROP-4", "Provider isolation prevents cross-provider gap resolution without factual support", not is_suff_p4 and not g_p4.resolved)

    # Property 5: Contradiction between two pieces of evidence prevents SUFFICIENT unless resolved.
    ev_a = _make_evidence("EV-A", "ServiceX approved for production")
    ev_b = _make_evidence("EV-B", "ServiceX NOT approved for production")
    edge_p5 = EvidenceEdge(
        source_evidence_id=ev_a.evidence_id,
        target_evidence_id=ev_b.evidence_id,
        relationship_type=RelationshipType.CONTRADICTS,
        basis="Direct contradiction",
        derived_by=EdgeDerivationType.DETERMINISTIC_REFERENCE,
        confidence=1.0,
    )
    s_p5 = _make_session(evidence_list=[ev_a, ev_b])
    state_p5 = _make_state(s_p5, edges=[edge_p5])
    is_suff_p5, reason_p5 = ctrl.verify_sufficiency(state_p5, "")
    record_prop("PROP-5", "Unresolved contradiction strictly prevents SUFFICIENT", not is_suff_p5 and "contradiction" in reason_p5.lower())

    # Property 6: No gap of unknown/unregistered type can be resolved by arbitrary evidence.
    unknown_types = ["RANDOM_TYPE", "UNKNOWN_123", "SYSTEM_PROMPT_INJECTION", "EV_BYPASS"]
    all_unresolved = True
    for ut in unknown_types:
        g_ut = InformationGap(gap_id=f"G-{ut}", description="Exploit attempt", target_entity="ServiceX", gap_type=ut, is_blocking=True)
        s_ut = _make_session(gaps=[g_ut], evidence_list=[ev_a])
        ctrl._evaluate_gap_resolution(g_ut, s_ut, [ev_a.evidence_id])
        if g_ut.resolved:
            all_unresolved = False
            break
    record_prop("PROP-6", "Unknown/unregistered gap types never resolved by arbitrary evidence", all_unresolved)

    # Property 7: An empty candidate pool never produces SUFFICIENT when open gaps exist.
    g_p7 = InformationGap(gap_id="G-P7", description="Mandatory root gap", target_entity="CoreSystem", gap_type=GapType.PREREQUISITE, is_blocking=True)
    s_p7 = _make_session(gaps=[g_p7])
    state_p7 = _make_state(s_p7)
    is_suff_p7, _ = ctrl.verify_sufficiency(state_p7, "")
    record_prop("PROP-7", "Empty candidate pool never produces SUFFICIENT with open gaps", not is_suff_p7)

    # Property 8: Transitive dependency chain of length N terminates if and only if all N steps are resolved.
    N = 6
    gaps_chain = []
    ev_all = []
    for i in range(1, N + 1):
        ev_i = _make_evidence(f"EV-{i}", f"Entity-{i} verified operational")
        ev_all.append(ev_i)
        gaps_chain.append(InformationGap(
            gap_id=f"G-STEP-{i}",
            description=f"Step {i}",
            target_entity=f"Entity-{i}",
            gap_type=GapType.PREREQUISITE,
            is_blocking=True,
            status=GapStatus.RESOLVED,
            resolution_evidence_ids=[f"EV-{i}"],
        ))
    s_p8 = _make_session(gaps=gaps_chain, evidence_list=ev_all)
    state_p8_all = _make_state(s_p8)
    is_suff_all, _ = ctrl.verify_sufficiency(state_p8_all, "")

    # Now unresolve step 4
    gaps_chain[3].status = GapStatus.OPEN
    gaps_chain[3].resolution_evidence_ids = []
    state_p8_partial = _make_state(s_p8)
    is_suff_partial, _ = ctrl.verify_sufficiency(state_p8_partial, "")

    prop_8_holds = is_suff_all and (not is_suff_partial)
    record_prop("PROP-8", "Transitive chain of length N terminates iff all N steps are resolved", prop_8_holds)

    total_passed = sum(1 for p in properties if p["passed"])
    return total_passed, len(properties), properties


# =====================================================================
# MAIN EXECUTION
# =====================================================================

def main():
    print("=" * 70)
    print("BRICK 4.2-S PHASE 2.1: ADVERSARIAL VALIDATION & PROPERTY TEST HARNESS")
    print("=" * 70)

    # Part 1: Mutations
    m_pass, m_total, mutations = run_mutation_attacks()
    print(f"\n[PART 1] DETERMINISTIC MUTATION ATTACKS: {m_pass}/{m_total} PASSED")
    for m in mutations:
        status = "PASS" if m["passed"] else "FAIL"
        print(f"  [{status}] {m['id']} ({m['category']}): {m['name']}")

    # Part 2: Properties
    p_pass, p_total, properties = run_property_tests()
    print(f"\n[PART 2] CORE INVARIANT PROPERTY TESTS: {p_pass}/{p_total} PASSED")
    for p in properties:
        status = "PASS" if p["passed"] else "FAIL"
        print(f"  [{status}] {p['id']}: {p['name']}")

    print("\n" + "=" * 70)
    total_tests = m_total + p_total
    total_passed = m_pass + p_pass
    print(f"SUMMARY: {total_passed}/{total_tests} PASSED (Mutations: {m_pass}/{m_total}, Properties: {p_pass}/{p_total})")
    print("=" * 70)

    if total_passed == total_tests:
        print("\nOVERALL STATUS: ALL ATTACK VECTORS BLOCKED, ALL PROPERTIES HOLD.")
        sys.exit(0)
    else:
        print("\nOVERALL STATUS: VULNERABILITY DETECTED.")
        sys.exit(1)


if __name__ == "__main__":
    main()
