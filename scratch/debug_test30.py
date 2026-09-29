from tests.unit.test_brick35b_intelligence import MockRetriever, make_evidence
from backend.investigation.controller import InvestigationController, InvestigationBudget, InformationGap, GapType, InvestigationState

retriever = MockRetriever()
retriever.add_canned_response("can we safely onboard", [
    make_evidence("EV-INIT-VEND", "Vendor Assessment: Evaluating AcmeCloud vendor security and legal profile.", "DOC-INIT"),
])
retriever.add_canned_response("acmecloud vendor onboarding contracts", [
    make_evidence("EV-CONTRACT", "Vendor Onboarding: AcmeCloud MSA and SLA contracts APPROVED by legal.", "DOC-LEGAL"),
    make_evidence("EV-SOC2", "Compliance Status: AcmeCloud SOC-2 Type II audit report VALID and compliance confirmed.", "DOC-COMPL"),
])
retriever.add_canned_response("acmecloud security review", [
    make_evidence("EV-VEND-SEC", "InfoSec Review: AcmeCloud network penetration test PASSED with 0 Sev-1 issues.", "DOC-SEC"),
])

budget = InvestigationBudget(max_hops=4, max_llm_calls=5, max_queries=15)
ctrl = InvestigationController(retriever=retriever, budget=budget)

def reasoning_agent(state: InvestigationState):
    accum = set(state.accumulated_evidence.keys())
    if "EV-CONTRACT" not in accum:
        return False, "Check contracts and compliance", [
            InformationGap(gap_id="GAP-CONTRACT", gap_type=GapType.PREREQUISITE, is_blocking=True, target_entity="AcmeCloud", description="Legal approval", targeted_query="AcmeCloud vendor onboarding contracts")
        ], []
    if "EV-VEND-SEC" not in accum:
        return False, "Check InfoSec validation", [
            InformationGap(gap_id="GAP-SEC", gap_type=GapType.PREREQUISITE, is_blocking=True, target_entity="AcmeCloud", description="Security validation", targeted_query="AcmeCloud security review")
        ], []
    return True, "Vendor onboarding gates fully satisfied", [], []

package = ctrl.run_investigation("Can we safely onboard Vendor AcmeCloud?", reasoning_agent_fn=reasoning_agent)

print("Termination reason:", package.termination_reason)
for e in package.investigation_trace:
    print(f"[{e.hop}] {e.event_type}: {e.description} | {e.details}")
