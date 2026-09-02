"""
ORACLE Investigation Engine (Brick 3, 3.1 & 3.2)
Connects the Deterministic Investigation Controller with the local LLM reasoning plane.
Implements:
  - P1 (Brick 3.2): Dependency-directed investigation prompting
  - First-class InvestigationGap instantiation with originating evidence IDs
  - Compact 1-line Evidence State Index
  - Minimal structured LLM output (is_sufficient + 1-2 targeted search queries)
"""

from typing import Any, Dict, List, Optional, Tuple
from pydantic import BaseModel, Field, field_validator

from backend.inference.base import LLMProvider
from backend.investigation.controller import InvestigationController
from backend.investigation.models import (
    EdgeDerivationType,
    EvidenceEdge,
    EvidencePackage,
    InvestigationBudget,
    InvestigationGap,
    InvestigationState,
    RelationshipType,
)
from backend.retrieval.fts5_retriever import SQLiteFTS5Retriever


# -----------------------------------------------------------------------------
# COMPACT SCHEMAS (BRICK 3.1 & 3.2)
# -----------------------------------------------------------------------------
class CompactGapProposal(BaseModel):
    """Surgical search query proposal (2-5 keywords) targeting a dependency (P1)."""
    priority: int = Field(ge=1, le=2, description="1=High (blocking), 2=Medium")
    targeted_query: str = Field(description="2 to 5 specific search keywords targeting an unresolved dependency or system")
    target_entity: str = Field(description="Specific subsystem, change, or ticket investigated (e.g. Redis, CR-904, mTLS)")
    required_information: str = Field(default="", description="What specific fact this query seeks to prove")


class CompactStepProposal(BaseModel):
    """Minimum required structured representation for LLM step proposal."""
    is_sufficient: bool = Field(description="Propose True ONLY if accumulated evidence completely proves or refutes the objective")
    candidate_queries: List[CompactGapProposal] = Field(
        default_factory=list,
        description="1 or 2 targeted search queries if insufficient",
    )


# -----------------------------------------------------------------------------
# LEGACY SCHEMAS (PRESERVED FOR BACKWARD COMPATIBILITY)
# -----------------------------------------------------------------------------
class ProposedInferredEdge(BaseModel):
    source_evidence_id: str
    target_evidence_id: str
    relationship_type: RelationshipType
    basis: str
    confidence: float = Field(ge=0.0, le=1.0)

    @field_validator("confidence", mode="before")
    @classmethod
    def normalize_confidence(cls, v: Any) -> float:
        if isinstance(v, (int, float)) and v > 1.0:
            return float(v) / 100.0
        return float(v)


class CandidateGapProposal(BaseModel):
    gap_id: str
    priority: int = Field(ge=1, le=3, description="1=High (blocking), 2=Medium, 3=Low")
    description: str
    targeted_query: str
    rationale: str


class LLMInvestigationStepProposal(BaseModel):
    is_sufficient: bool = Field(description="Propose True if accumulated evidence completely proves or refutes the objective")
    sufficiency_rationale: str = Field(description="Explanation of why evidence is or is not sufficient")
    candidate_gaps: List[CandidateGapProposal] = Field(default_factory=list, description="0 to 3 missing factual requirements")
    proposed_inferred_edges: List[ProposedInferredEdge] = Field(default_factory=list, description="Hypothesized relationship edges")


# -----------------------------------------------------------------------------
# INVESTIGATION ENGINE
# -----------------------------------------------------------------------------
class InvestigationEngine:
    """
    Top-level engine for running evidence-guided investigations.
    Utilizes Compact State representation and dependency-directed prompting (P1).
    """

    def __init__(
        self,
        retriever: SQLiteFTS5Retriever,
        llm_provider: LLMProvider,
        budget: Optional[InvestigationBudget] = None,
    ):
        self.retriever = retriever
        self.llm_provider = llm_provider
        self.budget = budget or InvestigationBudget()
        self.controller = InvestigationController(retriever=self.retriever, budget=self.budget)

    def investigate(self, objective: str) -> EvidencePackage:
        """
        Run an autonomous, evidence-guided investigation for the given objective.
        """
        def reasoning_agent_callback(
            state: InvestigationState,
        ) -> Tuple[bool, str, List[InvestigationGap], List[EvidenceEdge]]:
            return self._call_llm_for_step(state)

        return self.controller.run_investigation(
            objective=objective,
            reasoning_agent_fn=reasoning_agent_callback,
        )

    def _call_llm_for_step(
        self,
        state: InvestigationState,
    ) -> Tuple[bool, str, List[InvestigationGap], List[EvidenceEdge]]:
        """
        Construct compact state prompt with dependency-directed instructions (P1)
        and parse response into verified InvestigationGap objects.
        """
        prompt = self._build_compact_prompt(state)

        response = self.llm_provider.generate_structured(
            prompt=prompt,
            schema=CompactStepProposal,
        )

        if isinstance(response, CompactStepProposal):
            proposal = response
        elif hasattr(response, "parsed") and response.parsed is not None:
            proposal = response.parsed
        else:
            proposal = response

        originating_ids = list(state.accumulated_evidence.keys())
        gaps = [
            InvestigationGap(
                gap_id=f"GAP-{idx+1}",
                priority=q.priority,
                description=f"Query targeting {q.target_entity}: {q.required_information or q.targeted_query}",
                targeted_query=q.targeted_query,
                required_information=q.required_information or f"Status and requirements for {q.target_entity}",
                candidate_queries=[q.targeted_query],
                originating_evidence_ids=originating_ids,
                attempted_queries=[],
                resolution_status=False,
                resolution_evidence_ids=[],
            )
            for idx, q in enumerate(proposal.candidate_queries)
        ]

        edges: List[EvidenceEdge] = []
        return proposal.is_sufficient, "", gaps, edges

    def _build_compact_prompt(self, state: InvestigationState) -> str:
        """
        Construct concise representation of the accumulated state:
          - Evidence Index (1 line per chunk)
          - Known Contradictions & Superseded Claims
          - Unresolved References / Open Changes
          - Failed Zero-Yield Queries (P3)
          - Executed Query History
          - Dependency-directed instructions (P1)
        """
        index_lines = []
        for ev in state.accumulated_evidence.values():
            section = ev.metadata.get("section", "General")
            preview = ev.content.replace("\n", " ")[:80]
            index_lines.append(f"- [{ev.evidence_id}] ({section}): \"{preview}...\"")
        compact_index = "\n".join(index_lines)

        conflict_lines = []
        for edge in state.evidence_graph:
            if edge.relationship_type in [RelationshipType.CONTRADICTS, RelationshipType.SUPERSEDES]:
                conflict_lines.append(
                    f"- [{edge.source_evidence_id}] {edge.relationship_type.value} [{edge.target_evidence_id}]: {edge.basis}"
                )
        conflicts_text = "\n".join(conflict_lines) if conflict_lines else "None detected yet"

        unresolved_text = ", ".join(sorted(state.unresolved_references)) if state.unresolved_references else "None"
        failed_queries_text = ", ".join(f'"{q}"' for q in sorted(state.zero_yield_queries)) if state.zero_yield_queries else "None"
        executed_text = ", ".join(f'"{q}"' for q in sorted(state.executed_queries)) if state.executed_queries else "None"

        return f"""OBJECTIVE:
{state.objective}

CURRENT EVIDENCE INDEX ({len(state.accumulated_evidence)} items):
{compact_index}

KNOWN CONFLICTS / SUPERSEDED CLAIMS:
{conflicts_text}

UNRESOLVED REFERENCES / OPEN CHANGES:
{unresolved_text}

FAILED QUERIES (RETURNED 0 RESULTS - DO NOT RETRY OR PARAPHRASE):
{failed_queries_text}

ALREADY EXECUTED QUERIES:
{executed_text}

CRITICAL INVESTIGATION DIRECTIVES (P1):
1. DO NOT restate or paraphrase the overall objective as a search query.
2. Formulate 1 to 2 targeted search queries (2 to 5 keywords) that specifically investigate:
   - Unresolved operational prerequisites or dependencies mentioned in the evidence (e.g. if an evidence item mentions Payment Gateway requires Redis v7.2 mTLS, search for the active Redis version or mTLS status).
   - Status, approval, or rejection of referenced change requests (e.g. CR-904).
   - Root causes or rollbacks of cited incidents (e.g. INC-402).
3. Propose is_sufficient = True ONLY when all required operational dependencies are fully verified by evidence.
"""
