"""
ORACLE Investigation Engine (Brick 3.4 Revision v2 + Brick 3.7 Adaptive Retrieval)
Connects the Deterministic Investigation Controller with the local LLM reasoning plane.
Implements:
  - Domain-agnostic InformationGap presentation
  - Compact 1-line Evidence State Index + Active Open Gaps Ledger
  - Minimal structured LLM output (is_sufficient proposal + 1-2 targeted search queries)
  - Configurable Adaptive Retrieval integration
"""

from typing import Any, Dict, List, Optional, Tuple
from pydantic import BaseModel, Field, field_validator

from backend.inference.base import LLMProvider
from backend.investigation.controller import InvestigationController
from backend.investigation.models import (
    AdaptiveRetrievalConfig,
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


# -----------------------------------------------------------------------------
# COMPACT SCHEMAS
# -----------------------------------------------------------------------------
class CompactGapProposal(BaseModel):
    """Surgical search query proposal (2-5 keywords) targeting an open requirement."""
    priority: int = Field(default=1, ge=1, le=2, description="1=High (blocking), 2=Medium")
    targeted_query: str = Field(description="2 to 5 specific search keywords targeting the active gap")
    target_entity: str = Field(description="Specific subsystem, component, change, or ticket investigated")
    required_information: str = Field(default="", description="What specific fact this query seeks to prove")


class CompactStepProposal(BaseModel):
    """Minimum required structured representation for LLM step proposal."""
    is_sufficient: bool = Field(default=False, description="Propose True ONLY if accumulated evidence completely proves or refutes the objective")
    candidate_queries: List[CompactGapProposal] = Field(
        default_factory=list,
        description="1 or 2 targeted search queries targeting the active open gaps",
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
    Utilizes Compact State representation and domain-agnostic gap resolution.
    """

    def __init__(
        self,
        retriever: SQLiteFTS5Retriever,
        llm_provider: LLMProvider,
        budget: Optional[InvestigationBudget] = None,
        adaptive_retrieval_config: Optional[AdaptiveRetrievalConfig] = None,
    ):
        self.retriever = retriever
        self.llm_provider = llm_provider
        self.budget = budget or InvestigationBudget()
        self.adaptive_config = adaptive_retrieval_config or AdaptiveRetrievalConfig()
        self.controller = InvestigationController(
            retriever=self.retriever,
            budget=self.budget,
            adaptive_retrieval_config=self.adaptive_config,
        )

    def investigate(self, objective: str, initial_k: Optional[int] = None) -> EvidencePackage:
        """
        Run an autonomous, evidence-guided investigation for the given objective.
        """
        def reasoning_agent_callback(
            state: InvestigationState,
        ) -> Tuple[bool, str, List[InformationGap], List[EvidenceEdge]]:
            return self._call_llm_for_step(state)

        return self.controller.run_investigation(
            objective=objective,
            reasoning_agent_fn=reasoning_agent_callback,
            initial_k=initial_k,
        )

    def _call_llm_for_step(
        self,
        state: InvestigationState,
    ) -> Tuple[bool, str, List[InformationGap], List[EvidenceEdge]]:
        """
        Construct compact state prompt with active open gaps and parse response.
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
            InformationGap(
                gap_id=f"GAP-PROP-{idx+1}",
                gap_type=GapType.PREREQUISITE,
                priority=q.priority,
                description=f"Query targeting {q.target_entity}: {q.required_information or q.targeted_query}",
                targeted_query=q.targeted_query,
                target_entity=q.target_entity,
                required_information=q.required_information or f"Status and requirements for {q.target_entity}",
                candidate_queries=[q.targeted_query],
                originating_evidence_ids=originating_ids,
                attempted_queries=[],
                status=GapStatus.OPEN,
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
          - Active Open Information Gaps
          - Failed Zero-Yield Searches
          - Executed Query History
          - Domain-agnostic directives
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

        # Active open gaps
        gap_lines = []
        for g in state.pending_gaps:
            gap_lines.append(f"- [{g.gap_id}] (Target: {g.target_entity}): {g.required_information}")
        open_gaps_text = "\n".join(gap_lines) if gap_lines else "None pending"

        unresolved_text = ", ".join(sorted(state.unresolved_references)) if state.unresolved_references else "None"
        failed_queries_text = ", ".join(f'"{q}"' for q in sorted(state.zero_yield_queries)) if state.zero_yield_queries else "None"
        executed_text = ", ".join(f'"{q}"' for q in sorted(state.executed_queries)) if state.executed_queries else "None"

        return f"""OBJECTIVE:
{state.objective}

CURRENT EVIDENCE INDEX ({len(state.accumulated_evidence)} items):
{compact_index}

KNOWN CONFLICTS / SUPERSEDED CLAIMS:
{conflicts_text}

ACTIVE OPEN INFORMATION GAPS:
{open_gaps_text}

UNRESOLVED REFERENCES / OPEN CHANGES:
{unresolved_text}

FAILED QUERIES (RETURNED 0 RESULTS - DO NOT RETRY OR PARAPHRASE):
{failed_queries_text}

ALREADY EXECUTED QUERIES:
{executed_text}

CRITICAL INVESTIGATION DIRECTIVES (P1):
1. DO NOT restate or paraphrase the overall objective as a search query.
2. Formulate 1 to 2 targeted search queries (2 to 5 keywords) that directly investigate the highest-priority active open gap.
3. Target the specific entity, decision, version, or prerequisite required by the open gap.
"""
