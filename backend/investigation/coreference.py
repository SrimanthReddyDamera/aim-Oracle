"""
Entity Coreference Resolution Subsystem for ORACLE (Brick 3.5B)

Provides controlled, high-confidence anaphora and reference resolution across sentences
within evidence chunks, preventing false entity attribution while enabling evaluation of
clauses with implicit entity references (e.g., 'Project Phoenix was scheduled for Friday.
It was subsequently cancelled due to Sev-1.').
"""

from __future__ import annotations

import re
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

from pydantic import BaseModel, Field


class ReferenceCategory(str, Enum):
    PROJECT = "PROJECT"
    TICKET_CHANGE = "TICKET_CHANGE"
    TICKET_INCIDENT = "TICKET_INCIDENT"
    SERVICE_SYSTEM = "SERVICE_SYSTEM"
    GENERIC_PRONOUN = "GENERIC_PRONOUN"


class CoreferenceBinding(BaseModel):
    """Provenance-preserving record of an inferred coreference link."""
    clause_index: int
    clause_text: str
    reference_expression: str
    antecedent_entity: str
    confidence: float
    resolution_method: str
    is_ambiguous: bool = False
    provenance: Dict[str, Any] = Field(default_factory=dict)


class ResolvedClause(BaseModel):
    """A segmented clause enriched with explicit and high-confidence coreferent entities."""
    clause_index: int
    clause_text: str
    explicit_entities: Set[str] = Field(default_factory=set)
    inferred_bindings: List[CoreferenceBinding] = Field(default_factory=list)
    effective_entities: Set[str] = Field(default_factory=set)


# Entity category heuristics
ENTITY_CATEGORY_PATTERNS: Dict[ReferenceCategory, List[str]] = {
    ReferenceCategory.TICKET_INCIDENT: [r"\binc(?:ident)?-?\d+\b"],
    ReferenceCategory.TICKET_CHANGE: [r"\b(?:cr|rfc|ticket|change)-?\d+\b"],
    ReferenceCategory.PROJECT: [r"\bproject\s+[a-z0-9_\-]+|\bphoenix\b"],
    ReferenceCategory.SERVICE_SYSTEM: [
        r"\b(?:payment\s+gateway|checkout\s+service|auth(?:entication)?(?:\s+server)?|redis(?:\s+cluster)?|kafka(?:\s+broker)?|postgres(?:\s+database)?|cab|change\s+advisory\s+board)\b"
    ],
}

# Reference expression definitions
REFERENCE_EXPRESSIONS: List[Tuple[re.Pattern, ReferenceCategory, float]] = [
    (re.compile(r"\bthis\s+project\b", re.IGNORECASE), ReferenceCategory.PROJECT, 0.95),
    (re.compile(r"\bthe\s+project\b", re.IGNORECASE), ReferenceCategory.PROJECT, 0.90),
    (re.compile(r"\bthis\s+change\b", re.IGNORECASE), ReferenceCategory.TICKET_CHANGE, 0.95),
    (re.compile(r"\bthe\s+ticket\b", re.IGNORECASE), ReferenceCategory.TICKET_CHANGE, 0.90),
    (re.compile(r"\bthis\s+incident\b", re.IGNORECASE), ReferenceCategory.TICKET_INCIDENT, 0.95),
    (re.compile(r"\bthe\s+incident\b", re.IGNORECASE), ReferenceCategory.TICKET_INCIDENT, 0.90),
    (re.compile(r"\bthe\s+deployment\b", re.IGNORECASE), ReferenceCategory.TICKET_CHANGE, 0.85),
    (re.compile(r"\bthe\s+migration\b", re.IGNORECASE), ReferenceCategory.PROJECT, 0.85),
    (re.compile(r"\bthis\s+service\b", re.IGNORECASE), ReferenceCategory.SERVICE_SYSTEM, 0.90),
    (re.compile(r"\bthe\s+service\b", re.IGNORECASE), ReferenceCategory.SERVICE_SYSTEM, 0.85),
    (re.compile(r"\b(?:it|its)\b", re.IGNORECASE), ReferenceCategory.GENERIC_PRONOUN, 0.85),
    (re.compile(r"\b(?:they|their)\b", re.IGNORECASE), ReferenceCategory.GENERIC_PRONOUN, 0.80),
]


class ControlledCoreferenceResolver:
    """
    Precision-first coreference resolver for evidence texts.
    Enforces the rule: 'False attribution is worse than missed attribution'.
    Ambiguous pronouns with multiple active antecedents are left strictly unresolved.
    """

    def __init__(self, confidence_threshold: float = 0.80):
        self.confidence_threshold = confidence_threshold

    def _segment_clauses(self, text: str) -> List[str]:
        """Segment raw evidence text into discrete clauses/sentences."""
        # Split on sentence punctuation or paragraph breaks
        raw_parts = re.split(r"(?<=[.!?;\n])\s+", text.strip())
        return [p.strip() for p in raw_parts if p.strip()]

    def _extract_entities_with_categories(self, text: str) -> Dict[str, ReferenceCategory]:
        """Extract entities and categorize them."""
        found: Dict[str, ReferenceCategory] = {}
        norm = text.lower()

        for cat, patterns in ENTITY_CATEGORY_PATTERNS.items():
            for pat in patterns:
                for match in re.finditer(pat, norm, re.IGNORECASE):
                    val = match.group(0).strip().upper()
                    # Normalize common aliases
                    if "PHOENIX" in val:
                        val = "PROJECT PHOENIX"
                    elif "CAB" in val or "CHANGE ADVISORY" in val:
                        val = "CAB"
                    elif "PAYMENT" in val or "CHECKOUT" in val:
                        val = "PAYMENT GATEWAY"
                    found[val] = cat
        return found

    def resolve_chunk(self, text: str) -> List[ResolvedClause]:
        """
        Analyze an evidence chunk, segment into clauses, track salient antecedents,
        and resolve high-confidence, unambiguous coreferences.
        """
        clauses = self._segment_clauses(text)
        resolved_clauses: List[ResolvedClause] = []

        # History of antecedents: list of (clause_idx, entity_name, category)
        antecedent_history: List[Tuple[int, str, ReferenceCategory]] = []

        for idx, clause in enumerate(clauses):
            explicit = self._extract_entities_with_categories(clause)
            effective = set(explicit.keys())
            inferred_bindings: List[CoreferenceBinding] = []

            # If clause mentions explicit entities, add them to history
            for ent, cat in explicit.items():
                antecedent_history.append((idx, ent, cat))

            # Look for reference expressions in the clause
            for regex, ref_cat, base_conf in REFERENCE_EXPRESSIONS:
                match = regex.search(clause)
                if not match:
                    continue

                ref_expr = match.group(0)

                # Find candidate antecedents from preceding clauses
                # (prefer the most recent antecedent)
                candidates = [
                    (c_idx, ent, cat)
                    for c_idx, ent, cat in antecedent_history
                    if c_idx < idx
                ]

                if not candidates:
                    # No prior antecedent -> cannot bind
                    continue

                # Filter by category if reference expression is category-specific
                if ref_cat != ReferenceCategory.GENERIC_PRONOUN:
                    matched_candidates = [
                        (c_idx, ent, cat) for c_idx, ent, cat in candidates if cat == ref_cat
                    ]
                else:
                    # Generic pronoun ("it", "they"): look at immediate preceding clause
                    matched_candidates = [
                        (c_idx, ent, cat) for c_idx, ent, cat in candidates if c_idx == idx - 1
                    ]

                if not matched_candidates:
                    continue

                # Ambiguity check:
                # If there are multiple distinct entities in the immediate prior clause or
                # matching the specific category, generic pronoun is ambiguous!
                unique_candidate_entities = {ent for _, ent, _ in matched_candidates}

                if len(unique_candidate_entities) > 1:
                    # AMBIGUOUS: Do NOT bind! False attribution is worse than missed attribution.
                    inferred_bindings.append(
                        CoreferenceBinding(
                            clause_index=idx,
                            clause_text=clause,
                            reference_expression=ref_expr,
                            antecedent_entity=list(unique_candidate_entities)[0],
                            confidence=0.40,
                            resolution_method="AMBIGUOUS_MULTIPLE_ANTECEDENTS",
                            is_ambiguous=True,
                            provenance={
                                "candidates": list(unique_candidate_entities),
                                "reason": "Multiple distinct entities competing for anaphora without category disambiguation",
                            },
                        )
                    )
                    continue

                # Exactly ONE unambiguous candidate!
                chosen_c_idx, chosen_entity, chosen_cat = matched_candidates[-1]

                # Distance penalty: If antecedent is > 2 clauses away, reduce confidence
                distance = idx - chosen_c_idx
                confidence = base_conf
                if distance > 1:
                    confidence -= (distance - 1) * 0.10

                is_confident = confidence >= self.confidence_threshold
                binding = CoreferenceBinding(
                    clause_index=idx,
                    clause_text=clause,
                    reference_expression=ref_expr,
                    antecedent_entity=chosen_entity,
                    confidence=confidence,
                    resolution_method="DETERMINISTIC_ADJACENT_ANAPHORA" if distance == 1 else "CATEGORY_ANCHORED_ANAPHORA",
                    is_ambiguous=False,
                    provenance={
                        "distance_clauses": distance,
                        "antecedent_clause_idx": chosen_c_idx,
                        "antecedent_category": chosen_cat.value,
                        "reference_category": ref_cat.value,
                    },
                )
                inferred_bindings.append(binding)

                if is_confident:
                    effective.add(chosen_entity)

            resolved_clauses.append(
                ResolvedClause(
                    clause_index=idx,
                    clause_text=clause,
                    explicit_entities=set(explicit.keys()),
                    inferred_bindings=inferred_bindings,
                    effective_entities=effective,
                )
            )

        return resolved_clauses
