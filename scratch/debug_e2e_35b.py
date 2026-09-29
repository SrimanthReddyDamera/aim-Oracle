from tests.unit.test_brick35a_hardening import make_test_evidence, MockMemoryRetriever
from backend.investigation.controller import InvestigationController, InvestigationBudget, InformationGap, GapType, GapStatus, InvestigationState

ev_init = make_test_evidence(
    "DOC-INIT",
    "Project Phoenix Launch Overview: Launch requires Security CAB authorization CR-888 "
    "and Database migration MIG-200.",
    created_at="2026-10-24T08:00:00Z",
)
ev_app = make_test_evidence(
    "DOC-CR-888-APP",
    "Security CAB Meeting #88: Change request CR-888 is APPROVED for Friday launch.",
    created_at="2026-10-24T09:00:00Z",
)
ev_mig = make_test_evidence(
    "DOC-MIG-200",
    "Database Migration Log: MIG-200 schema update executed successfully and verified.",
    created_at="2026-10-24T09:30:00Z",
)
ev_revoke = make_test_evidence(
    "DOC-CR-888-REVOKE",
    "EMERGENCY SECURITY NOTICE: Change request CR-888 is DENIED and CANCELLED due to audit findings.",
    created_at="2026-10-24T10:00:00Z",
)
ev_reauth = make_test_evidence(
    "DOC-CR-888-REAUTH",
    "Security CAB Special Session DECISION: CR-888 audit findings addressed; re-authorization APPROVED and VALID. SUPERSEDES earlier revocation.",
    created_at="2026-10-24T11:00:00Z",
)
ev_smoke = make_test_evidence(
    "DOC-VAL-SMOKE",
    "Phoenix End-to-End Validation: Automated smoke test suite PASSED with 100% success rate.",
    created_at="2026-10-24T12:00:00Z",
)

retriever = MockMemoryRetriever()
retriever.add_canned_response("phoenix readiness", [ev_init])
retriever.add_canned_response("cr-888 decision", [ev_app])
retriever.add_canned_response("cr-888 approval", [ev_app])
retriever.add_canned_response("mig-200", [ev_mig])
retriever.add_canned_response("emergency security notice", [ev_revoke])
retriever.add_canned_response("security cab special session", [ev_reauth])
retriever.add_canned_response("reconcile cr-888", [ev_reauth])
retriever.add_canned_response("phoenix smoke", [ev_smoke])

budget = InvestigationBudget(max_hops=6, max_llm_calls=8, max_queries=30)
controller = InvestigationController(retriever=retriever, budget=budget)

def guided_reasoning_agent(state: InvestigationState):
    accum_ids = set(state.accumulated_evidence.keys())
    has_auth_app = "DOC-CR-888-APP" in accum_ids
    has_mig = "DOC-MIG-200" in accum_ids
    has_revoke = "DOC-CR-888-REVOKE" in accum_ids
    has_reauth = "DOC-CR-888-REAUTH" in accum_ids
    has_smoke = "DOC-VAL-SMOKE" in accum_ids

    if not has_auth_app:
        gap_auth = InformationGap(
            gap_id="GAP-AUTH",
            gap_type=GapType.AUTHORITY_RESOLUTION,
            is_blocking=True,
            description="Verify CAB authorization CR-888",
            target_entity="CR-888",
            required_information="CR-888 approval status",
            targeted_query="CR-888 approval",
        )
        return False, "Searching for CAB authorization", [gap_auth], []

    if not has_mig:
        gap_mig = InformationGap(
            gap_id="GAP-MIG",
            gap_type=GapType.PREREQUISITE,
            is_blocking=True,
            description="Verify database migration MIG-200",
            target_entity="MIG-200",
            required_information="MIG-200 execution status",
            targeted_query="MIG-200 schema update",
        )
        return False, "Searching for migration execution", [gap_mig], []

    if not has_revoke:
        gap_contra = InformationGap(
            gap_id="GAP-AUDIT",
            gap_type=GapType.CONTRADICTION_RECONCILIATION,
            is_blocking=True,
            description="Check latest security audit notices",
            target_entity="CR-888",
            required_information="CR-888 security audit notices",
            targeted_query="EMERGENCY SECURITY NOTICE CR-888",
        )
        return False, "Checking security audit notices", [gap_contra], []

    if not has_reauth:
        gap_resolve = InformationGap(
            gap_id="GAP-RECONCILE",
            gap_type=GapType.CONTRADICTION_RECONCILIATION,
            is_blocking=True,
            description="Reconcile CR-888 disposition",
            target_entity="CR-888",
            required_information="CR-888 Special Session re-authorization",
            targeted_query="Security CAB Special Session CR-888",
        )
        return False, "Investigating contradiction reconciliation", [gap_resolve], []

    if not has_smoke:
        gap_smoke = InformationGap(
            gap_id="GAP-SMOKE",
            gap_type=GapType.PREREQUISITE,
            is_blocking=True,
            description="Verify end-to-end smoke test suite",
            target_entity="Phoenix",
            required_information="Automated smoke test suite PASSED",
            targeted_query="Phoenix smoke test suite",
        )
        return False, "Gathering final smoke test validation", [gap_smoke], []

    return True, "All prerequisites gathered, contradiction reconciled, validation passed.", [], []

package = controller.run_investigation(
    objective="Verify Project Phoenix readiness for Friday launch",
    reasoning_agent_fn=guided_reasoning_agent,
    initial_k=1,
)

print("Termination reason:", package.termination_reason)
print("Trace events:")
for e in package.investigation_trace:
    print(f"[{e.hop}] {e.event_type}: {e.description} | {e.details}")
