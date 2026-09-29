"""
ORACLE Investigation Planner (Brick 3.4)
Responsible for:
  1. Parsing the user's objective/question to establish what must be known.
  2. Generating candidate hypotheses (affirmative and counter/risk hypotheses).
  3. Formulating explicit, controller-owned InformationGap objects.
  4. Deduplicating semantically equivalent gaps.
  5. Deterministically prioritizing gaps.
  6. Determining controller-governed next investigation actions with explicit reasons.

EPISTEMIC INVARIANTS:
  - The Controller owns all mutable state and gap transitions.
  - The LLM can propose, but the Controller validates and decides.
  - No blind repeated searches of the original question.
  - Every action must have an explicit reason tied to an originating gap.
"""

from datetime import datetime, timezone
import re
from typing import Any, Dict, List, Optional, Set, Tuple
import uuid

from backend.investigation.entity_scanner import EntityScanner
from backend.investigation.models import (
    ActionStatus,
    ActionType,
    GapStatus,
    GapType,
    InformationGap,
    InvestigationAction,
    InvestigationHypothesis,
    InvestigationPlan,
)

STOPWORDS = {
    "a", "an", "the", "is", "are", "was", "were", "and", "or", "in", "on", "at",
    "to", "for", "of", "with", "by", "from", "can", "what", "how", "this", "that",
    "it", "its", "be", "do", "does", "did", "under", "before", "after", "should",
    "could", "would", "we", "safely", "friday", "monday", "tuesday", "wednesday",
    "thursday", "saturday", "sunday", "today", "tomorrow"
}

CALENDAR_AND_TIME_WORDS = {
    "january", "february", "march", "april", "may", "june", "july", "august",
    "september", "october", "november", "december", "monday", "tuesday",
    "wednesday", "thursday", "friday", "saturday", "sunday", "today", "tomorrow",
    "utc", "gmt", "est", "pst", "cst", "edt", "pdt", "cdt"
}

PROMPT_QUESTION_WORDS = {
    "can", "we", "verify", "check", "investigate", "determine", "assess",
    "confirm", "what", "is", "are", "how", "why", "when", "where", "will",
    "should", "could", "would", "please", "if"
}

GENERIC_NOISER_WORDS = {
    "VERIFY", "CHECK", "FIND", "REQUIREMENTS", "REQUIREMENT", "STATUS",
    "OPERATIONAL", "DETAILS", "INFORMATION", "INFO", "STATE", "IDENTIFY",
    "PROVIDE", "SEARCH", "SYSTEM", "SERVICE", "COMPONENT"
}


class InvestigationPlanner:
    """
    Controller-owned planner that establishes hypotheses, information requirements,
    deduplicated gaps, and targeted investigation actions.
    """

    def __init__(
        self,
        scanner: Optional[EntityScanner] = None,
        llm_provider: Optional[Any] = None,
        jaccard_threshold: float = 0.70,
    ):
        self.scanner = scanner or EntityScanner()
        self.llm_provider = llm_provider
        self.jaccard_threshold = jaccard_threshold

    def plan(
        self,
        objective: str,
        priority_evaluator: Optional[Any] = None,
    ) -> InvestigationPlan:
        """
        Formulate a structured InvestigationPlan for the given user objective.
        1. Parse question & extract entities/intent.
        2. Generate candidate hypotheses.
        3. Formulate explicit InformationGaps.
        4. Deduplicate semantically equivalent gaps.
        5. Prioritize gaps.
        6. Formulate targeted candidate action(s).
        """
        now_iso = datetime.now(timezone.utc).isoformat()

        # 1. Parse question and extract entity references
        extracted_refs = self.scanner.extract_references(objective)
        tokens_found: Set[str] = set()
        for ref_set in extracted_refs.values():
            tokens_found.update(ref_set)

        named_entities = self._extract_named_entities(objective)

        # 2. Formulate Candidate Hypotheses
        hypotheses = self._generate_hypotheses(objective, named_entities, tokens_found)

        # 3. Formulate Candidate Information Gaps
        candidate_gaps: List[InformationGap] = []

        primary_entity = named_entities[0] if named_entities else "Root Objective"
        root_query = self._derive_root_query(objective, named_entities)

        # Root gap
        candidate_gaps.append(
            InformationGap(
                gap_id="GAP-ROOT-1",
                gap_type=GapType.OBJECTIVE_ROOT,
                priority_score=100.0,
                is_blocking=True,
                description=f"Core factual requirement: {objective.strip()}",
                why_needed="Primary question posed by user requires direct factual resolution",
                evidence_requirement=objective.strip(),
                target_entity=primary_entity,
                required_information=objective.strip(),
                targeted_query=root_query,
                candidate_queries=[root_query],
                status=GapStatus.OPEN,
                provenance={"source": "PLANNER", "type": "ROOT", "created_at": now_iso},
            )
        )

        # Gaps for explicit ticket/document references
        for token in sorted(tokens_found):
            cat = self.scanner.classify_token(token)
            gid = f"GAP-REF-{token}"
            if cat == "INCIDENT":
                desc = f"Authoritative incident resolution and current state for {token}"
                why = f"Incident {token} referenced in objective may block operational readiness"
                req = f"Resolution status and postmortem for {token}"
                query = f"{token} current production state"
                gtype = GapType.AUTHORITY_RESOLUTION
            elif cat == "CHANGE_REQUEST":
                desc = f"Change request decision and deployment disposition for {token}"
                why = f"Change {token} requires authoritative CAB approval and verification"
                req = f"Approval disposition and validation for {token}"
                query = f"{token} decision disposition"
                gtype = GapType.AUTHORITY_RESOLUTION
            elif cat == "DOC_ID":
                desc = f"Specification and operational requirements in document {token}"
                why = f"Document {token} contains binding technical constraints"
                req = f"Operational constraints specified in {token}"
                query = f"{token} operational specification"
                gtype = GapType.PREREQUISITE
            else:
                desc = f"Verification of entity {token}"
                why = f"Direct entity reference {token} requires verification"
                req = f"Status and requirements for {token}"
                query = token
                gtype = GapType.PREREQUISITE

            candidate_gaps.append(
                InformationGap(
                    gap_id=gid,
                    gap_type=gtype,
                    priority_score=90.0,
                    is_blocking=True,
                    description=desc,
                    why_needed=why,
                    evidence_requirement=req,
                    target_entity=token,
                    required_information=req,
                    targeted_query=query,
                    candidate_queries=[query],
                    status=GapStatus.OPEN,
                    provenance={"source": "PLANNER", "token": token, "created_at": now_iso},
                )
            )

        # Gaps for secondary named entities / subsystems (non-blocking candidate requirements)
        for entity in named_entities[1:]:
            if entity.upper() in tokens_found or len(entity) < 3:
                continue
            clean_id = re.sub(r"[^A-Za-z0-9]+", "-", entity.upper()).strip("-")
            gid = f"GAP-ENTITY-{clean_id[:24]}"
            target_q = f"{entity} requirements status"
            candidate_gaps.append(
                InformationGap(
                    gap_id=gid,
                    gap_type=GapType.PREREQUISITE,
                    priority_score=60.0,
                    is_blocking=False,
                    description=f"Operational prerequisite verification for {entity}",
                    why_needed=f"Subsystem {entity} is mentioned in objective and may be a prerequisite component",
                    evidence_requirement=f"Operational requirements and readiness of {entity}",
                    target_entity=entity,
                    required_information=f"Operational requirements and status for {entity}",
                    targeted_query=target_q,
                    candidate_queries=[target_q],
                    status=GapStatus.OPEN,
                    provenance={"source": "PLANNER", "entity": entity, "created_at": now_iso},
                )
            )

        # 4. Deduplicate semantically equivalent gaps
        deduped_gaps = self.deduplicate_gaps(candidate_gaps)

        # 5. Prioritize gaps
        for gap in deduped_gaps:
            if priority_evaluator:
                gap.priority_score = priority_evaluator(gap)
            else:
                gap.priority_score = self._default_priority_score(gap)
            # Transition safely OPEN -> PLANNED
            gap.status = GapStatus.PLANNED

        deduped_gaps.sort(key=lambda g: g.priority_score, reverse=True)

        # 6. Determine candidate investigation actions
        planned_actions: List[InvestigationAction] = []
        action_idx = 1
        for gap in deduped_gaps:
            q = gap.targeted_query or (gap.candidate_queries[0] if gap.candidate_queries else gap.target_entity)
            if q and gap.gap_id != "GAP-ROOT-1":
                planned_actions.append(
                    InvestigationAction(
                        action_id=f"ACT-PLAN-{action_idx:02d}",
                        gap_id=gap.gap_id,
                        action_type=ActionType.SEARCH,
                        query=q,
                        reason=f"Investigate high-priority gap {gap.gap_id}: {gap.description}",
                        status=ActionStatus.PROPOSED,
                    )
                )
                action_idx += 1

        if not planned_actions and deduped_gaps:
            root_gap = deduped_gaps[0]
            q = root_gap.targeted_query or root_gap.target_entity
            planned_actions.append(
                InvestigationAction(
                    action_id="ACT-PLAN-01",
                    gap_id=root_gap.gap_id,
                    action_type=ActionType.SEARCH,
                    query=q,
                    reason=f"Initial discovery for root gap {root_gap.gap_id}",
                    status=ActionStatus.PROPOSED,
                )
            )

        # Architectural guard against investigation branching explosion (P2):
        # Bound candidate gaps to top 10 and planned initial actions to top 5.
        if len(deduped_gaps) > 10:
            root_g = [g for g in deduped_gaps if g.gap_id == "GAP-ROOT-1"]
            other_g = [g for g in deduped_gaps if g.gap_id != "GAP-ROOT-1"]
            deduped_gaps = root_g + other_g[:9]

        planned_actions = planned_actions[:5]

        return InvestigationPlan(
            objective=objective,
            hypotheses=hypotheses,
            gaps=deduped_gaps,
            planned_actions=planned_actions,
        )

    def deduplicate_gaps(self, gaps: List[InformationGap]) -> List[InformationGap]:
        """
        Deduplicates semantically equivalent gaps using entity matching and token Jaccard similarity.
        Merges queries and provenance when duplicate is detected.
        """
        unique_gaps: List[InformationGap] = []

        for candidate in gaps:
            is_dup = False
            for existing in unique_gaps:
                # 1. Exact ID match
                if candidate.gap_id == existing.gap_id:
                    self._merge_gap_content(existing, candidate)
                    is_dup = True
                    break

                # 2. Same target entity and high semantic overlap
                entity_match = (
                    candidate.target_entity.strip().lower() == existing.target_entity.strip().lower()
                    and bool(candidate.target_entity)
                )
                cand_tokens = self._tokenize(f"{candidate.description} {candidate.required_information}")
                exist_tokens = self._tokenize(f"{existing.description} {existing.required_information}")
                intersection = cand_tokens.intersection(exist_tokens)
                union = cand_tokens.union(exist_tokens)
                jaccard = len(intersection) / len(union) if union else 0.0

                if entity_match and (jaccard >= self.jaccard_threshold or not cand_tokens or not exist_tokens):
                    self._merge_gap_content(existing, candidate)
                    is_dup = True
                    break
                elif jaccard >= 0.85:
                    self._merge_gap_content(existing, candidate)
                    is_dup = True
                    break

            if not is_dup:
                unique_gaps.append(candidate)

        return unique_gaps

    def _merge_gap_content(self, target: InformationGap, source: InformationGap) -> None:
        """Merge candidate queries, required facts, and originating evidence from duplicate gap."""
        for q in source.candidate_queries:
            if q not in target.candidate_queries:
                target.candidate_queries.append(q)
        for f in source.required_facts:
            if f not in target.required_facts:
                target.required_facts.append(f)
        for eid in source.originating_evidence_ids:
            if eid not in target.originating_evidence_ids:
                target.originating_evidence_ids.append(eid)
        if not target.targeted_query and source.targeted_query:
            target.targeted_query = source.targeted_query
        if not target.why_needed and source.why_needed:
            target.why_needed = source.why_needed
        if not target.evidence_requirement and source.evidence_requirement:
            target.evidence_requirement = source.evidence_requirement

    def _generate_hypotheses(
        self,
        objective: str,
        named_entities: List[str],
        tokens: Set[str],
    ) -> List[InvestigationHypothesis]:
        """Generate structured affirmative and risk hypotheses for the investigation."""
        target_str = ", ".join(named_entities) if named_entities else "the target system"
        h1 = InvestigationHypothesis(
            hypothesis_id="HYP-01-AFFIRMATIVE",
            statement=f"All operational prerequisites, dependencies, and requirements for {target_str} are fully satisfied.",
            status="PROPOSED",
            rationale="Initial baseline hypothesis assuming operational readiness",
        )
        h2 = InvestigationHypothesis(
            hypothesis_id="HYP-02-RISK",
            statement=f"Unresolved incidents, rollback states, or conflicting configurations block readiness for {target_str}.",
            status="PROPOSED",
            rationale="Safety hypothesis tracking potential blockers or contradictions",
        )
        return [h1, h2]

    def _extract_named_entities(self, text: str) -> List[str]:
        """Extract clean multi-word capitalized phrases or technical keywords from question."""
        entities: List[str] = []
        # Pattern 1: Title Cased phrases (e.g. Project Phoenix, Payment Gateway)
        matches = re.findall(r"\b[A-Z][a-z]+(?:\s+[A-Z][a-z]+)+\b", text)
        for m in matches:
            words = m.split()
            # Strip leading prompt/question words
            while words and words[0].lower() in PROMPT_QUESTION_WORDS:
                words.pop(0)
            # Strip trailing time/calendar words
            while words and words[-1].lower() in CALENDAR_AND_TIME_WORDS:
                words.pop()
            if not words:
                continue
            if any(w.lower() in CALENDAR_AND_TIME_WORDS for w in words):
                continue
            clean_m = " ".join(words).strip()
            if len(clean_m) < 3 or clean_m.lower() in CALENDAR_AND_TIME_WORDS or clean_m.lower() in STOPWORDS:
                continue
            if clean_m not in entities:
                entities.append(clean_m)

        # Pattern 2: CamelCase or acronyms (e.g. mTLS, CAB, Redis)
        single_caps = re.findall(r"\b[A-Z]{2,10}\b|\b[A-Z][a-z]{2,}\b", text)
        for sc in single_caps:
            sc_lower = sc.lower()
            if (
                sc_lower not in STOPWORDS
                and sc_lower not in CALENDAR_AND_TIME_WORDS
                and sc_lower not in PROMPT_QUESTION_WORDS
                and sc.upper() not in GENERIC_NOISER_WORDS
                and len(sc) >= 3
            ):
                # Do not add single word if it is already part of an extracted multi-word phrase
                if not any(re.search(rf"\b{re.escape(sc)}\b", e, re.IGNORECASE) for e in entities):
                    entities.append(sc)

        return entities

    def _derive_root_query(self, objective: str, entities: List[str]) -> str:
        """Derive targeted 2-4 keyword search query rather than echoing the full question."""
        obj_words = [w for w in objective.strip().split() if w.lower() not in STOPWORDS]
        if len(obj_words) <= 3:
            return objective.strip()
        if entities:
            return entities[0]
        tokens = [
            t for t in re.findall(r"\b[A-Za-z0-9\-]+\b", objective)
            if t.lower() not in STOPWORDS and len(t) > 2
        ]
        return " ".join(tokens[:4]) if tokens else objective[:40].strip()

    def _tokenize(self, text: str) -> Set[str]:
        tokens = set(re.findall(r"\b[a-z0-9\-]+\b", text.lower())) - STOPWORDS
        return {t for t in tokens if len(t) > 2 and t.upper() not in GENERIC_NOISER_WORDS}

    def _default_priority_score(self, gap: InformationGap) -> float:
        score = 0.0
        if gap.is_blocking:
            score += 100.0
        if gap.gap_type == GapType.CONTRADICTION_RECONCILIATION or gap.conflicting_evidence_ids:
            score += 50.0
        elif gap.gap_type in [GapType.AUTHORITY_RESOLUTION, GapType.PREREQUISITE]:
            score += 25.0
        return score
