"""
ORACLE Brick 3.1: Controlled Single-Scenario Performance Diagnostic
Scenario: INV-01 (Q-13) - "Can Project Phoenix safely launch this Friday, October 24 at 09:00 UTC?"

Strict Constraints:
  - Baseline unoptimized Brick 3 implementation
  - No timeout inflation (keeps default budget)
  - No new features or integrations
  - Captures complete step-by-step LLM and Controller telemetry
"""

import json
import sys
import time
from pathlib import Path
import httpx

# Enable unbuffered line-level streaming for immediate output
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(line_buffering=True)

project_root = Path("C:/Users/damer/OneDrive/Desktop/aim- ORACLE")
sys.path.insert(0, str(project_root))

from backend.evidence.parser import MarkdownEvidenceParser
from backend.investigation.controller import InvestigationController
from backend.investigation.entity_scanner import EntityScanner
from backend.investigation.engine import LLMInvestigationStepProposal
from backend.investigation.models import (
    EdgeDerivationType,
    EvidenceEdge,
    InformationGap,
    InvestigationBudget,
    InvestigationState,
    RelationshipType,
)
from backend.retrieval.fts5_retriever import SQLiteFTS5Retriever

CORPUS_DIR = project_root / "tests" / "test_data" / "nova_corpus"
MANIFEST_PATH = CORPUS_DIR / "manifest.json"


def run_controlled_diagnostic():
    print("=" * 85, flush=True)
    print("      ORACLE BRICK 3.1: CONTROLLED PERFORMANCE DIAGNOSTIC (INV-01)", flush=True)
    print("=" * 85, flush=True)

    # 1. Ingest Corpus into FTS5
    parser = MarkdownEvidenceParser()
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    all_chunks = []
    for doc in manifest["documents"]:
        all_chunks.extend(parser.parse_file(CORPUS_DIR / doc["filename"]))

    retriever = SQLiteFTS5Retriever(":memory:")
    build_ms = retriever.index_evidence(all_chunks)
    print(f"[+] Corpus indexed: {len(all_chunks)} chunks in {build_ms:.2f} ms.", flush=True)

    objective = "Can Project Phoenix safely launch this Friday, October 24 at 09:00 UTC?"
    print(f"[+] Objective: \"{objective}\"", flush=True)

    # Baseline budget with default timeout
    budget = InvestigationBudget(
        max_hops=3,
        max_llm_calls=3,
        max_queries=6,
        max_total_chunks=15,
        max_wall_time_seconds=30.0,
    )
    print(f"[+] Budget Config: max_hops={budget.max_hops}, max_llm_calls={budget.max_llm_calls}, timeout={budget.max_wall_time_seconds}s", flush=True)

    scanner = EntityScanner()
    controller = InvestigationController(retriever=retriever, scanner=scanner, budget=budget)

    step_telemetry = []

    def instrumented_reasoning_agent(state: InvestigationState):
        hop_idx = state.hop_count + 1
        print(f"\n--- [HOP {hop_idx}] LLM INVOCATION TRACE ---", flush=True)

        # Step A: Prompt Construction
        t0_construct = time.perf_counter()
        evidence_snippets = []
        total_evidence_chars = 0
        for ev in state.accumulated_evidence.values():
            snippet = f"[{ev.evidence_id}] (Source: {ev.source_id})\n{ev.content[:250]}..."
            evidence_snippets.append(snippet)
            total_evidence_chars += len(snippet)
        evidence_text = "\n\n".join(evidence_snippets)

        prompt = f"""You are the ORACLE Investigation Reasoning Advisor.
Your job is to inspect the current evidence against the user objective, identify missing information gaps, and propose 0 to 3 targeted FTS5 search queries.

OBJECTIVE:
{state.objective}

CURRENT ACCUMULATED EVIDENCE ({len(state.accumulated_evidence)} chunks):
{evidence_text}

INSTRUCTIONS:
1. Assess whether the current evidence provides an unbroken, factual chain of evidence that proves or refutes the objective.
2. If NOT sufficient, formulate 1 to 3 candidate missing information gaps with concrete 2-5 keyword queries.
3. Propose any inferred dependency or causal relationships between existing evidence chunks.
4. Output MUST conform strictly to the required schema.
"""
        construct_time_ms = (time.perf_counter() - t0_construct) * 1000.0

        json_schema = LLMInvestigationStepProposal.model_json_schema()
        system_instructions = (
            "You are a strict, deterministic structured reasoning engine. "
            "You must output ONLY a valid JSON object matching the provided JSON schema. "
            "Do not include any conversational filler, markdown codeblocks, or extra text."
        )

        payload = {
            "model": "qwen2.5:3b",
            "prompt": prompt,
            "system": system_instructions,
            "format": json_schema,
            "stream": False,
            "options": {"temperature": 0.0},
        }

        print(f"  [1] Prompt Construction:  {construct_time_ms:.3f} ms", flush=True)
        print(f"  [2] Evidence Chunks Sent: {len(state.accumulated_evidence)} chunks ({total_evidence_chars} chars)", flush=True)
        print(f"  [3] Total Prompt Chars:   {len(prompt)} chars", flush=True)

        # Step B: Direct Call to Ollama API
        t0_http = time.perf_counter()
        with httpx.Client(timeout=180.0) as client:
            res = client.post("http://127.0.0.1:11434/api/generate", json=payload)
        http_wall_clock_s = time.perf_counter() - t0_http

        data = res.json()
        raw_text = data.get("response", "").strip()

        # Telemetry extraction
        load_duration_ms = data.get("load_duration", 0) / 1e6
        prompt_eval_count = data.get("prompt_eval_count", 0)
        prompt_eval_duration_s = data.get("prompt_eval_duration", 0) / 1e9
        eval_count = data.get("eval_count", 0)
        eval_duration_s = data.get("eval_duration", 0) / 1e9
        total_ollama_s = data.get("total_duration", 0) / 1e9

        prompt_speed = (prompt_eval_count / prompt_eval_duration_s) if prompt_eval_duration_s > 0 else 0.0
        gen_speed = (eval_count / eval_duration_s) if eval_duration_s > 0 else 0.0

        print(f"  [4] Model Disk Load Time: {load_duration_ms:.2f} ms", flush=True)
        print(f"  [5] Input Tokens:         {prompt_eval_count} tokens", flush=True)
        print(f"  [6] Input Eval Time:      {prompt_eval_duration_s:.2f} s ({prompt_speed:.1f} tokens/sec)", flush=True)
        print(f"  [7] Output Tokens:        {eval_count} tokens", flush=True)
        print(f"  [8] Output Gen Time:      {eval_duration_s:.2f} s ({gen_speed:.1f} tokens/sec)", flush=True)
        print(f"  [9] Total HTTP Latency:   {http_wall_clock_s:.2f} s", flush=True)

        # Step C: Parse Structured Model
        parsed_proposal = LLMInvestigationStepProposal.model_validate_json(raw_text)

        gaps = [
            InformationGap(
                gap_id=g.gap_id,
                priority=g.priority,
                description=g.description,
                targeted_query=g.targeted_query,
                rationale=g.rationale,
                resolved=False,
            )
            for g in parsed_proposal.candidate_gaps
        ]

        edges = [
            EvidenceEdge(
                source_evidence_id=e.source_evidence_id,
                target_evidence_id=e.target_evidence_id,
                relationship_type=e.relationship_type,
                basis=e.basis,
                derived_by=EdgeDerivationType.LLM_INFERENCE,
                confidence=e.confidence,
            )
            for e in parsed_proposal.proposed_inferred_edges
            if e.source_evidence_id in state.accumulated_evidence
            and e.target_evidence_id in state.accumulated_evidence
        ]

        telemetry_record = {
            "hop": hop_idx,
            "construct_time_ms": round(construct_time_ms, 3),
            "evidence_chunks_count": len(state.accumulated_evidence),
            "prompt_chars": len(prompt),
            "input_tokens": prompt_eval_count,
            "input_eval_seconds": round(prompt_eval_duration_s, 2),
            "input_tokens_per_sec": round(prompt_speed, 1),
            "output_tokens": eval_count,
            "output_gen_seconds": round(eval_duration_s, 2),
            "output_tokens_per_sec": round(gen_speed, 1),
            "load_duration_ms": round(load_duration_ms, 2),
            "total_ollama_seconds": round(total_ollama_s, 2),
            "http_wall_clock_seconds": round(http_wall_clock_s, 2),
            "proposed_sufficient": parsed_proposal.is_sufficient,
            "candidate_gaps_count": len(gaps),
            "inferred_edges_count": len(edges),
        }
        step_telemetry.append(telemetry_record)

        print(f"  [10] LLM Proposal:        is_sufficient={parsed_proposal.is_sufficient}", flush=True)
        print(f"  [11] Gaps Formulated:     {len(gaps)}", flush=True)
        for g in gaps:
            print(f"       - [{g.gap_id}] P{g.priority}: \"{g.targeted_query}\"", flush=True)

        return parsed_proposal.is_sufficient, parsed_proposal.sufficiency_rationale, gaps, edges

    # Run Investigation
    t_start_total = time.perf_counter()
    package = controller.run_investigation(
        objective=objective,
        reasoning_agent_fn=instrumented_reasoning_agent,
        initial_k=4,
    )
    total_run_time_s = time.perf_counter() - t_start_total

    print("\n" + "=" * 85, flush=True)
    print("                    FINAL CONTROLLER INVESTIGATION OUTCOME", flush=True)
    print("=" * 85, flush=True)
    print(f"Termination Reason:     {package.termination_reason}", flush=True)
    print(f"Controller Verified:    {package.controller_verified}", flush=True)
    print(f"Hops Completed:         {package.budget_summary['hops_used']}", flush=True)
    print(f"LLM Calls Completed:    {package.budget_summary['llm_calls_used']}", flush=True)
    print(f"Queries Executed:       {package.budget_summary['queries_executed']}", flush=True)
    print(f"Total Chunks Collected: {len(package.evidence_items)}", flush=True)
    print(f"Total Wall-Clock Time:  {total_run_time_s:.2f} s", flush=True)
    print("=" * 85, flush=True)

    # Save Diagnostic Report to JSON
    diagnostic_payload = {
        "scenario": "INV-01",
        "objective": objective,
        "budget": budget.model_dump(),
        "total_wall_clock_seconds": round(total_run_time_s, 2),
        "termination_reason": package.termination_reason,
        "controller_verified": package.controller_verified,
        "step_telemetry": step_telemetry,
        "package_summary": {
            "evidence_ids": [e.evidence_id for e in package.evidence_items],
            "graph_edges": [e.model_dump() for e in package.graph_edges],
            "gap_history": package.gap_history,
        }
    }
    out_file = project_root / "experiments" / "controlled_diagnostic_inv01_results.json"
    out_file.write_text(json.dumps(diagnostic_payload, indent=2), encoding="utf-8")
    print(f"\n[+] Full diagnostic results written to: {out_file}\n", flush=True)


if __name__ == "__main__":
    run_controlled_diagnostic()
