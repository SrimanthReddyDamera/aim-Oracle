from tests.unit.test_brick35b_intelligence import MockRetriever, make_evidence
from backend.investigation.controller import InvestigationController, InvestigationBudget, InformationGap, GapType, InvestigationState

retriever = MockRetriever()
retriever.add_canned_response("payment gateway", [
    make_evidence("EV-CR-48", "CAB DECISION: Change request CR-48 for Payment Gateway v4.8 is APPROVED for deployment tonight.", "DOC-CAB-48"),
    make_evidence("EV-SEC-48", "Security Review: Payment Gateway v4.8 mTLS cryptographic handshake validation PASSED.", "DOC-SEC-48"),
])
retriever.add_canned_response("rollback", [
    make_evidence("EV-RB-48", "Operational Plan: Payment Gateway v4.8 rollback plan verified and backup confirmed.", "DOC-OPS-48"),
])

budget = InvestigationBudget(max_hops=4, max_llm_calls=5, max_queries=15)
ctrl = InvestigationController(retriever=retriever, budget=budget)

def reasoning_agent(state: InvestigationState):
    accum = set(state.accumulated_evidence.keys())
    if "EV-CR-48" not in accum:
        return False, "Check CAB approval", [
            InformationGap(gap_id="GAP-CAB", gap_type=GapType.AUTHORITY_RESOLUTION, is_blocking=True, target_entity="Payment Gateway", description="CAB approval", targeted_query="Payment Gateway CR-48 approval")
        ], []
    if "EV-RB-48" not in accum:
        return False, "Check rollback readiness", [
            InformationGap(gap_id="GAP-RB", gap_type=GapType.PREREQUISITE, is_blocking=True, target_entity="Payment Gateway", description="Rollback plan", targeted_query="Payment Gateway rollback plan")
        ], []
    return True, "All deployment gates satisfied", [], []

package = ctrl.run_investigation("Can Payment Gateway v4.8 safely deploy tonight?", reasoning_agent_fn=reasoning_agent)

print("Termination reason:", package.termination_reason)
print("Trace events:")
for e in package.investigation_trace:
    print(f"[{e.hop}] {e.event_type}: {e.description} | {e.details}")
