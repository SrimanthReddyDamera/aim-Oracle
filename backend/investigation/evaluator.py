"""
ORACLE Entity-Scoped & Claim-Aware Evidence Evaluator (Brick 3.5A)
Evaluates evidence chunks against InformationGaps with strict entity-clause scoping,
clause-level fact binding, substantive semantic coverage, and opposition detection.

CRITICAL INVARIANTS:
  1. Scope Isolation: Evidence must bind facts to the specific target entity within the same clause.
     Prevents cross-entity semantic bleed (e.g. Kafka v7.2 cannot satisfy Redis v7.2).
  2. Anti-Overlap Defense: A gap is NEVER satisfied by incidental single-token lexical overlap.
     Requires substantive predicate/property matching within the entity-matching clause.
  3. Contradiction Preservation: Opposing claims in the same clause or entity context
     strictly trigger conflict/reconciliation rather than false affirmative resolution.
"""

from dataclasses import dataclass, field
import re
from typing import Any, Dict, List, Optional, Set, Tuple

from enum import Enum
from pydantic import BaseModel, Field

from backend.evidence.models import Evidence
from backend.investigation.models import EvidencePackage, GapStatus, GapType, InformationGap
from backend.investigation.polarity import OppositionDomain, OppositionEngine, OppositionMatch, Polarity


class FailureClass(str, Enum):
    SUCCESS                     = "SUCCESS"
    INSUFFICIENT_CORPUS_CORRECT = "INSUFFICIENT_CORPUS_CORRECT"
    RETRIEVAL_FAILURE           = "RETRIEVAL_FAILURE"
    INVESTIGATION_FAILURE       = "INVESTIGATION_FAILURE"
    REASONING_FAILURE           = "REASONING_FAILURE"
    CONTROLLER_FAILURE          = "CONTROLLER_FAILURE"


class ScenarioEvaluationResult(BaseModel):
    scenario_id: str
    archetype: str
    objective: str
    expected_answerable: bool
    
    # Ground-truth evidence metrics
    required_evidence_recall: float
    required_evidence_found: List[str]
    required_evidence_missing: List[str]
    contradictory_evidence_discovered: Optional[float] = None
    contradictory_evidence_found: List[str] = Field(default_factory=list)
    irrelevant_evidence_ratio: float
    distractors_found: List[str] = Field(default_factory=list)
    
    # Controller contract metrics
    controller_verified: bool
    termination_reason: str
    successful_termination: bool
    premature_termination: bool
    unsupported_claim: bool
    max_hop_termination: bool
    stagnation_detected: bool
    
    # Resource metrics
    hops_used: int
    llm_calls_used: int
    queries_executed: int
    zero_yield_queries: int
    elapsed_seconds: float
    ram_rss_mb: float
    
    # Failure taxonomy
    failure_class: FailureClass
    failure_diagnosis: str


class InvestigationEvaluator:
    """
    100% Deterministic Evaluator for ORACLE investigations.
    Uses set operations and event trace audits. Zero LLM calls.
    """

    def evaluate_scenario(
        self,
        scenario_spec: Dict[str, Any],
        package: EvidencePackage,
        elapsed_seconds: float,
        ram_rss_mb: float,
    ) -> ScenarioEvaluationResult:
        retrieved_ids = set(e.evidence_id for e in package.evidence_items)
        req_set = set(scenario_spec.get("required_evidence_ids", []))
        contra_set = set(scenario_spec.get("contradictory_evidence_ids", []))
        distract_set = set(scenario_spec.get("distractor_evidence_ids", []))
        expected_answerable = scenario_spec.get("expected_answerable", True)

        found_req = req_set.intersection(retrieved_ids)
        missing_req = req_set - retrieved_ids
        found_contra = contra_set.intersection(retrieved_ids)
        found_distract = distract_set.intersection(retrieved_ids)

        # 1. Recall & Precision Metrics
        recall = (len(found_req) / len(req_set)) * 100.0 if req_set else 100.0
        contra_recall = (len(found_contra) / len(contra_set)) * 100.0 if contra_set else None

        # Noise / Irrelevant evidence ratio
        valid_set = req_set.union(contra_set)
        irrelevant_count = len(retrieved_ids - valid_set)
        irrelevant_ratio = (irrelevant_count / len(retrieved_ids)) * 100.0 if retrieved_ids else 0.0

        # 2. Controller Correctness Metrics
        max_hop_term = "MAX_HOPS" in package.termination_reason
        stagnation_term = "STAGNATION" in package.termination_reason

        premature_term = (package.controller_verified is True) and (recall < 100.0)
        unsupported_claim = premature_term

        if expected_answerable:
            successful_term = (package.controller_verified is True) and (recall == 100.0)
        else:
            successful_term = (package.controller_verified is False) and not premature_term

        # 3. Deterministic Failure Taxonomy Classification
        failure_class = FailureClass.SUCCESS
        diagnosis = "Investigation completed successfully with verified evidence completeness."

        if not expected_answerable:
            if package.controller_verified is False:
                failure_class = FailureClass.INSUFFICIENT_CORPUS_CORRECT
                diagnosis = "Corpus lacks necessary facts; controller correctly refused to verify sufficiency."
            else:
                failure_class = FailureClass.CONTROLLER_FAILURE
                diagnosis = "CRITICAL: Controller verified sufficiency for an unanswerable/insufficient question!"
        else:
            if premature_term:
                failure_class = FailureClass.CONTROLLER_FAILURE
                diagnosis = f"Controller granted sufficiency despite missing ground-truth chunks: {list(missing_req)}"
            elif recall < 100.0:
                llm_proposals = [e for e in package.investigation_trace if e.event_type == "LLM_PROPOSAL_RECEIVED"]
                had_premature_llm_proposal = any(e.details.get("proposed_sufficient") for e in llm_proposals)

                if had_premature_llm_proposal:
                    failure_class = FailureClass.REASONING_FAILURE
                    diagnosis = "LLM proposed sufficiency prematurely before all required evidence was collected."
                elif package.budget_summary.get("zero_yield_queries_count", 0) > 1:
                    failure_class = FailureClass.RETRIEVAL_FAILURE
                    diagnosis = "Targeted search queries repeatedly yielded zero new chunks from retriever index."
                else:
                    failure_class = FailureClass.INVESTIGATION_FAILURE
                    diagnosis = f"Investigation budget exhausted before discovering missing dependencies: {list(missing_req)}"
            else:
                failure_class = FailureClass.SUCCESS

        return ScenarioEvaluationResult(
            scenario_id=scenario_spec["scenario_id"],
            archetype=scenario_spec["archetype"],
            objective=scenario_spec["objective"],
            expected_answerable=expected_answerable,
            required_evidence_recall=round(recall, 1),
            required_evidence_found=sorted(list(found_req)),
            required_evidence_missing=sorted(list(missing_req)),
            contradictory_evidence_discovered=round(contra_recall, 1) if contra_recall is not None else None,
            contradictory_evidence_found=sorted(list(found_contra)),
            irrelevant_evidence_ratio=round(irrelevant_ratio, 1),
            distractors_found=sorted(list(found_distract)),
            controller_verified=package.controller_verified,
            termination_reason=package.termination_reason,
            successful_termination=successful_term,
            premature_termination=premature_term,
            unsupported_claim=unsupported_claim,
            max_hop_termination=max_hop_term,
            stagnation_detected=stagnation_term,
            hops_used=package.budget_summary["hops_used"],
            llm_calls_used=package.budget_summary["llm_calls_used"],
            queries_executed=package.budget_summary["queries_executed"],
            zero_yield_queries=package.budget_summary.get("zero_yield_queries_count", 0),
            elapsed_seconds=round(elapsed_seconds, 2),
            ram_rss_mb=round(ram_rss_mb, 1),
            failure_class=failure_class,
            failure_diagnosis=diagnosis,
        )


STOPWORDS = {
    "a", "an", "the", "is", "are", "was", "were", "and", "or", "in", "on", "at",
    "to", "for", "of", "with", "by", "from", "can", "what", "how", "this", "that",
    "it", "its", "be", "do", "does", "did", "under", "before", "after", "we",
    "should", "could", "would", "our", "all", "has", "have", "had", "been"
}

GENERIC_META_WORDS = {
    "VERIFY", "CHECK", "FIND", "REQUIREMENTS", "REQUIREMENT", "STATUS",
    "OPERATIONAL", "DETAILS", "INFORMATION", "INFO", "STATE", "IDENTIFY",
    "PROVIDE", "SEARCH", "SYSTEM", "SERVICE", "COMPONENT", "SPECIFICATION",
    "TECHNICAL", "CORE", "FACTUAL", "DETERMINE", "ASSESS", "CONFIRM"
}

GENERIC_ENTITY_NOUNS = {
    "SERVICE", "SERVICES", "COMPONENT", "COMPONENTS", "SYSTEM", "SYSTEMS",
    "MODULE", "MODULES", "GATEWAY", "GATEWAYS", "APP", "SERVER", "DATABASE",
    "CLUSTER", "CLUSTERS", "AGENT", "BROKER"
}

CLAUSE_SPLIT_PATTERN = re.compile(
    r"(?:(?:\.(?!\d)|[\!\?\;])\s+|\n\n+|\,\s*(?:while|whereas|although|but|however|despite)\s+)",
    re.IGNORECASE,
)


@dataclass
class GapEvaluationResult:
    """Detailed diagnostic outcome of evaluating an evidence chunk against a gap."""
    chunk_satisfies: bool = False
    chunk_conflicts: bool = False
    matched_clauses: List[str] = field(default_factory=list)
    conflicting_clauses: List[str] = field(default_factory=list)
    opposition_match: Optional[OppositionMatch] = None
    reason: str = ""

    @property
    def satisfies(self) -> bool:
        return self.chunk_satisfies

    @property
    def opposition_found(self) -> bool:
        return self.chunk_conflicts


EvaluationResult = GapEvaluationResult


class EntityScopedEvaluator:
    """
    Evaluates whether an Evidence chunk factually satisfies or contradicts an InformationGap.
    """

    def __init__(
        self,
        scanner: Optional[Any] = None,
        opposition_engine: Optional[OppositionEngine] = None,
        coref_resolver: Optional[Any] = None,
    ):
        self.scanner = scanner
        self.opposition_engine = opposition_engine or OppositionEngine()
        from backend.investigation.coreference import ControlledCoreferenceResolver
        self.coref_resolver = coref_resolver or ControlledCoreferenceResolver()

    def split_into_clauses(self, text: str) -> List[str]:
        """Split document chunk into discrete sentences and contrastive clauses."""
        raw_clauses = CLAUSE_SPLIT_PATTERN.split(text)
        cleaned = []
        for c in raw_clauses:
            s = " ".join(c.strip().split())
            if len(s) > 2:
                cleaned.append(s)
        return cleaned if cleaned else [text.strip()]

    def extract_entity_tokens(self, target_entity: str) -> List[str]:
        """Extract clean, substantive tokens of the target entity."""
        tokens = [
            t.upper() for t in re.findall(r"\b[A-Za-z0-9\.\-_]+\b", target_entity)
            if t.lower() not in STOPWORDS and len(t) > 1
        ]
        substantive = [t for t in tokens if t not in GENERIC_ENTITY_NOUNS]
        return substantive if substantive else tokens

    def match_entity_in_text(self, entity: str, text: str) -> bool:
        """
        Evaluate if target entity is specifically referenced in text with word boundaries.
        Supports multi-word phrase matching and substantive distinct token co-occurrence.
        """
        entity_clean = entity.strip()
        if not entity_clean:
            return False

        # Exact phrase match with word boundary
        if re.search(rf"\b{re.escape(entity_clean)}\b", text, re.IGNORECASE):
            return True

        # Normalized punctuation/hyphen-agnostic match
        norm_entity = re.sub(r"[\s\-_]+", " ", entity_clean).upper()
        norm_text = re.sub(r"[\s\-_]+", " ", text).upper()
        if re.search(rf"\b{re.escape(norm_entity)}\b", norm_text):
            return True

        substantive_tokens = self.extract_entity_tokens(entity_clean)
        if not substantive_tokens:
            return False

        # All substantive tokens of entity must co-occur in the same clause
        text_up = text.upper()
        return all(re.search(rf"\b{re.escape(t)}\b", text_up) for t in substantive_tokens)

    def match_fact_in_clause(self, fact: str, clause: str) -> bool:
        """
        Verify that all distinct substantive tokens of a required fact co-occur
        within the given entity-bound clause.
        """
        clause_up = clause.upper()
        fact_clean = fact.strip()

        # Direct substring match
        if fact_clean.upper() in clause_up:
            return True

        fact_tokens = [
            t.upper() for t in re.findall(r"\b[A-Za-z0-9\.\-_]+\b", fact_clean)
            if t.lower() not in STOPWORDS and len(t) > 1 and t.upper() not in GENERIC_META_WORDS
        ]
        if not fact_tokens:
            return False

        # Every distinct token of the fact must exist in this exact clause
        return all(re.search(rf"\b{re.escape(t)}\b", clause_up) for t in fact_tokens)

    def evaluate_substantive_requirement(
        self,
        gap: InformationGap,
        clause: str,
    ) -> Tuple[bool, float, List[str]]:
        """
        Evaluate substantive requirement coverage within an entity-matching clause.
        A single generic word can NEVER satisfy a substantive requirement.
        """
        req_text = gap.required_information or gap.description or gap.evidence_requirement
        req_tokens = [
            t.upper() for t in re.findall(r"\b[A-Za-z0-9\.\-_]+\b", req_text)
            if t.lower() not in STOPWORDS
            and t.upper() not in GENERIC_META_WORDS
            and t.upper() not in self.extract_entity_tokens(gap.target_entity)
            and len(t) > 2
        ]

        if not req_tokens:
            # If no substantive requirement tokens exist beyond entity, clause satisfies if entity matches
            return True, 1.0, []

        clause_up = clause.upper()
        matched = []
        for t in req_tokens:
            if re.search(rf"\b{re.escape(t)}\b", clause_up):
                matched.append(t)
            elif len(t) > 4:
                for suffix in ("ION", "ING", "ED", "ES", "AL", "E"):
                    if t.endswith(suffix):
                        stem = t[:-len(suffix)]
                        if len(stem) >= 3 and re.search(rf"\b{re.escape(stem)}[A-Z]*\b", clause_up):
                            matched.append(t)
                            break
        coverage = len(matched) / len(req_tokens)

        # STRICT DEFENSE:
        # If requirement has >= 2 substantive tokens, at least 2 distinct substantive tokens must match (>= 35% coverage).
        # If requirement has 1 substantive token, exact token must match.
        # A single incidental word match when required tokens > 1 is strictly rejected!
        if len(req_tokens) >= 2:
            is_satisfied = (len(matched) >= 2 and coverage >= 0.35) or (coverage >= 0.70)
        else:
            is_satisfied = (len(matched) == len(req_tokens))

        return is_satisfied, coverage, matched

    def get_gap_target_entity(self, gap: InformationGap) -> str:
        if gap.target_entity and gap.target_entity.strip():
            return gap.target_entity.strip()

        # Check for explicit reference tokens in gap_id, description, or query (e.g. INC-402, CR-904, SEC-412)
        combined = f"{gap.gap_id} {gap.description} {gap.targeted_query}".strip()
        ref_tokens = re.findall(r"\b[A-Z]{2,10}-\d{2,10}\b", combined)
        if ref_tokens:
            return ref_tokens[0]

        if gap.gap_id and gap.gap_id.startswith("GAP-"):
            parts = gap.gap_id.split("-")
            suffix = parts[-1] if len(parts) == 2 else "-".join(parts[2:]) if parts[1] in ["REF", "PREREQ", "DEP", "ENF", "ENTITY", "CONTRA"] else "-".join(parts[1:])
            if suffix and suffix.upper() not in GENERIC_META_WORDS:
                return suffix.replace("-", " ").strip()
        text = f"{gap.description} {gap.targeted_query}".strip()
        words = text.split()
        while words and words[0].upper() in GENERIC_META_WORDS:
            words.pop(0)
        filtered_text = " ".join(words)
        cap_phrases = re.findall(r"\b[A-Z][a-zA-Z0-9\.\-_]+(?:\s+[A-Z][a-zA-Z0-9\.\-_]+)*\b", filtered_text)
        for p in cap_phrases:
            p_up = p.upper()
            if p_up not in GENERIC_META_WORDS and p_up not in STOPWORDS and p_up not in GENERIC_ENTITY_NOUNS:
                return p
        return ""

    def evaluate_chunk(
        self,
        gap: InformationGap,
        evidence: Evidence,
    ) -> GapEvaluationResult:
        """
        Evaluate an Evidence chunk against an InformationGap using entity- and clause-level scoping.
        """
        result = GapEvaluationResult()
        clauses = self.split_into_clauses(f"{evidence.source_id}\n{evidence.content}")

        # Controlled Coreference Resolution across chunk
        resolved_clauses = self.coref_resolver.resolve_chunk(f"{evidence.source_id}\n{evidence.content}")
        coref_effective_map = {rc.clause_text.strip(): rc.effective_entities for rc in resolved_clauses}

        content_up = evidence.content.upper()
        source_up = evidence.source_id.upper()

        has_authoritative_header = (
            "DECISION:" in content_up
            or "FINAL RESOLUTION" in content_up
            or "SUPERSEDES" in content_up
            or "CURRENT PRODUCTION STATE" in content_up
            or "STATUS:" in content_up
        )

        if gap.gap_type == GapType.CONTRADICTION_RECONCILIATION:
            has_reconcile = (
                "SUPERSEDES" in content_up
                or "FINAL RESOLUTION" in content_up
                or "DECISION:" in content_up
                or "RECONCILED" in content_up
            )
            if has_reconcile:
                result.chunk_satisfies = True
                result.reason = "Authoritative superseding or reconciling record resolved conflicting claims"
                return result

        target_entity = self.get_gap_target_entity(gap)
        is_auth = (
            (self.scanner is not None and hasattr(self.scanner, "is_authoritative_resolution") and target_entity != "" and self.scanner.is_authoritative_resolution(target_entity, evidence))
            or (has_authoritative_header and (not target_entity or self.match_entity_in_text(target_entity, f"{source_up}\n{content_up}")))
        )

        for clause in clauses:
            clause_has_entity = False
            if target_entity:
                clause_has_entity = self.match_entity_in_text(target_entity, clause)
                if not clause_has_entity and self.match_entity_in_text(target_entity, source_up):
                    clause_has_entity = True
                if not clause_has_entity:
                    # Check if high-confidence coreference bound this clause to target_entity
                    effective_ents = coref_effective_map.get(clause.strip(), set())
                    target_norm = target_entity.upper()
                    if any(target_norm in ent or ent in target_norm for ent in effective_ents):
                        clause_has_entity = True
            else:
                is_subst, _, _ = self.evaluate_substantive_requirement(gap, clause)
                clause_has_entity = is_subst

            if not clause_has_entity:
                continue

            # 1. Check for semantic opposition between gap requirement and evidence clause, or negative markers
            req_text = gap.required_information or gap.description or gap.evidence_requirement
            opp_match = self.opposition_engine.detect_opposition(req_text, clause, target_entity=target_entity)
            has_neg = self.opposition_engine.has_negative_marker(clause)
            if opp_match or (has_neg and gap.gap_type in [GapType.AUTHORITY_RESOLUTION, GapType.CONTRADICTION_RECONCILIATION, GapType.PREREQUISITE]):
                result.chunk_conflicts = True
                if opp_match:
                    result.opposition_match = opp_match
                result.conflicting_clauses.append(clause)

            # Special case: Authority resolution records satisfy authority gaps
            if gap.gap_type == GapType.AUTHORITY_RESOLUTION and is_auth:
                result.chunk_satisfies = True
                result.matched_clauses.append(clause)
                continue

            # Special case: Reconciliation gaps are satisfied by authoritative records
            if gap.gap_type == GapType.CONTRADICTION_RECONCILIATION and is_auth:
                result.chunk_satisfies = True
                result.matched_clauses.append(clause)
                continue

            # 2. Check fact satisfaction within the same clause
            if gap.required_facts:
                facts_ok = all(self.match_fact_in_clause(f, clause) for f in gap.required_facts)
                if facts_ok:
                    if not opp_match:
                        result.chunk_satisfies = True
                        result.matched_clauses.append(clause)
            else:
                # Substantive requirement coverage check
                is_subst, cov, matched_toks = self.evaluate_substantive_requirement(gap, clause)
                if is_subst:
                    if not opp_match:
                        result.chunk_satisfies = True
                        result.matched_clauses.append(clause)

        # Global opposition check against resolution evidence
        if result.chunk_conflicts or result.chunk_satisfies:
            # Build diagnostic reason
            if result.chunk_conflicts and result.chunk_satisfies:
                result.reason = f"Chunk contains both satisfying and conflicting claims for entity '{gap.target_entity}'"
            elif result.chunk_conflicts:
                result.reason = f"Chunk expresses negative polarity/opposition for entity '{gap.target_entity}'"
            elif result.chunk_satisfies:
                result.reason = f"Chunk factually satisfies requirements for entity '{gap.target_entity}'"

        return result
