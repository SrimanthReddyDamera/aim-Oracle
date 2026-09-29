"""
Semantic Query Deduplication & Intent Representation Subsystem for ORACLE (Brick 3.5B)

Provides local, offline, deterministic semantic query deduplication, multi-layer intent
representation, and contextual compatibility analysis to protect investigation budgets
from semantic paraphrases without relying on cloud APIs or bypassing controller authority.
"""

from __future__ import annotations

import re
import threading
import time
from collections import OrderedDict
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

import numpy as np
from pydantic import BaseModel, Field

from backend.investigation.models import InformationGap


# -----------------------------------------------------------------------------
# 1. INTENT DOMAINS & MODELS
# -----------------------------------------------------------------------------

class InvestigativeOperation(str, Enum):
    APPROVAL = "APPROVAL"
    REJECTION = "REJECTION"
    EXECUTION = "EXECUTION"
    ROLLBACK = "ROLLBACK"
    VERIFICATION = "VERIFICATION"
    SECURITY = "SECURITY"
    REQUIREMENTS = "REQUIREMENTS"
    INCIDENT_STATUS = "INCIDENT_STATUS"
    BACKUP = "BACKUP"
    DELETION = "DELETION"
    GENERAL_QUERY = "GENERAL_QUERY"


OPERATION_LEXICON: Dict[InvestigativeOperation, Set[str]] = {
    InvestigativeOperation.APPROVAL: {
        "approve", "approved", "approval", "authorize", "authorized", "authorization",
        "signoff", "signed", "permit", "permitted", "ratify", "ratified", "passed"
    },
    InvestigativeOperation.REJECTION: {
        "reject", "rejected", "rejection", "deny", "denied", "disapprove", "disapproved",
        "cancel", "cancelled", "revoke", "revoked", "abort", "aborted"
    },
    InvestigativeOperation.EXECUTION: {
        "execute", "executed", "execution", "deploy", "deployed", "deployment",
        "apply", "applied", "migrate", "migrated", "migration", "run", "running"
    },
    InvestigativeOperation.ROLLBACK: {
        "rollback", "rolled back", "revert", "reverted", "undo", "undone", "restore", "restored"
    },
    InvestigativeOperation.VERIFICATION: {
        "verify", "verified", "validate", "validated", "validation", "test", "tested",
        "check", "checked", "health", "readiness", "audit", "compliance"
    },
    InvestigativeOperation.SECURITY: {
        "security", "tls", "mtls", "ssl", "handshake", "cryptographic", "crypto",
        "certificate", "encryption", "auth", "authentication", "token", "secret"
    },
    InvestigativeOperation.REQUIREMENTS: {
        "requirement", "requirements", "spec", "specification", "guideline", "guidelines",
        "prerequisite", "prerequisites", "config", "configuration", "protocol"
    },
    InvestigativeOperation.INCIDENT_STATUS: {
        "incident", "sev-1", "sev1", "outage", "failure", "remediation", "postmortem", "rca"
    },
    InvestigativeOperation.BACKUP: {
        "backup", "backups", "snapshot", "snapshots", "dump", "archive"
    },
    InvestigativeOperation.DELETION: {
        "delete", "deleted", "deletion", "remove", "removed", "purge", "purged", "teardown", "destroy"
    },
}

# Known semantic concept equivalences for offline expansion
CONCEPT_EQUIVALENCES: Dict[str, Set[str]] = {
    "payment gateway": {"checkout service", "payment processor", "billing service", "payment service"},
    "checkout service": {"payment gateway", "payment processor", "billing service", "payment service"},
    "mutual tls": {"mtls", "cryptographic handshake protocol", "two-way ssl", "client cert authentication"},
    "cryptographic handshake protocol": {"mutual tls", "mtls", "two-way ssl", "tls handshake"},
    "change advisory board": {"cab", "change board", "change approval board"},
    "cab": {"change advisory board", "change board", "change approval board"},
}


class QueryIntent(BaseModel):
    """Normalized multi-layer representation of investigative intent."""
    raw_query: str
    target_entity: Optional[str] = None
    target_gap_id: Optional[str] = None
    operation: InvestigativeOperation = InvestigativeOperation.GENERAL_QUERY
    identifiers: Set[str] = Field(default_factory=set)
    temporal_scope: Optional[str] = None
    semantic_text: str = ""
    normalized_tokens: Set[str] = Field(default_factory=set)

    model_config = {"arbitrary_types_allowed": True}


class SemanticDeduplicationResult(BaseModel):
    """Explicit deterministic decision object for query deduplication."""
    is_duplicate: bool
    similarity_score: float
    threshold: float
    comparison_query: Optional[str] = None
    contextual_compatibility: bool = True
    rejection_reason: Optional[str] = None
    provenance: Dict[str, Any] = Field(default_factory=dict)


# -----------------------------------------------------------------------------
# 2. LOCAL OFFLINE EMBEDDER
# -----------------------------------------------------------------------------

class BaseSemanticEmbedder:
    """Abstract interface for local/offline semantic embedding backends."""

    def embed(self, text: str) -> List[float]:
        raise NotImplementedError

    def similarity(self, vector_a: List[float], vector_b: List[float]) -> float:
        raise NotImplementedError


class LocalSemanticEmbeddingProvider(BaseSemanticEmbedder):
    """
    High-performance, local, deterministic sentence-encoder running offline.
    Uses subword n-gram hashing + semantic concept expansion + term weighting
    projected onto a normalized 256-dimensional unit hypersphere.
    """

    def __init__(self, dimensions: int = 256, cache_size: int = 2048):
        self.dimensions = dimensions
        self.cache_size = cache_size
        self._cache: OrderedDict[str, List[float]] = OrderedDict()
        self._lock = threading.Lock()

    def _hash_token(self, token: str, dim: int) -> int:
        """Deterministic 32-bit hash for a token/n-gram."""
        h = 2166136261
        for char in token:
            h = ((h ^ ord(char)) * 16777619) & 0xFFFFFFFF
        return h % dim

    def embed(self, text: str) -> List[float]:
        """Generate normalized 256-dim embedding vector for text with LRU caching."""
        norm_key = text.strip().lower()
        with self._lock:
            if norm_key in self._cache:
                self._cache.move_to_end(norm_key)
                return self._cache[norm_key]

        vec = np.zeros(self.dimensions, dtype=np.float32)
        words = re.findall(r"[a-z0-9#\-_]+", norm_key)
        expanded_concepts = []

        # Check concept equivalences
        full_text = " ".join(words)
        for concept, aliases in CONCEPT_EQUIVALENCES.items():
            if concept in full_text:
                expanded_concepts.append(concept)
                for alias in aliases:
                    expanded_concepts.append(alias)

        tokens_to_embed = list(words)
        for c in expanded_concepts:
            tokens_to_embed.extend(c.split())

        for token in tokens_to_embed:
            weight = 1.0
            if len(token) > 3:
                weight = 1.5
            # Word-level bucket
            idx = self._hash_token(token, self.dimensions)
            vec[idx] += weight * 1.0

            # Subword 3-grams for morphological resilience
            if len(token) >= 3:
                for i in range(len(token) - 2):
                    sub = token[i:i+3]
                    sub_idx = self._hash_token(sub, self.dimensions)
                    vec[sub_idx] += weight * 0.4

        # Unit normalize
        norm = np.linalg.norm(vec)
        if norm > 1e-8:
            vec = vec / norm
        else:
            vec[0] = 1.0

        res = vec.tolist()
        with self._lock:
            if len(self._cache) >= self.cache_size:
                self._cache.popitem(last=False)
            self._cache[norm_key] = res
        return res

    def similarity(self, vector_a: List[float], vector_b: List[float]) -> float:
        """Cosine similarity between two unit vectors."""
        a = np.asarray(vector_a, dtype=np.float32)
        b = np.asarray(vector_b, dtype=np.float32)
        norm_a = np.linalg.norm(a)
        norm_b = np.linalg.norm(b)
        if norm_a < 1e-8 or norm_b < 1e-8:
            return 0.0
        dot = float(np.dot(a, b) / (norm_a * norm_b))
        return max(-1.0, min(1.0, dot))


# -----------------------------------------------------------------------------
# 3. SEMANTIC QUERY DEDUPLICATOR
# -----------------------------------------------------------------------------

class SemanticQueryDeduplicator:
    """
    Multi-layer query deduplication engine combining:
    1. Lexical fast-filtering (cheap exact & high Jaccard matches)
    2. Structured intent extraction & contextual compatibility checks
    3. Dense semantic similarity evaluation
    """

    def __init__(
        self,
        embedder: Optional[BaseSemanticEmbedder] = None,
        semantic_threshold: float = 0.75,
        lexical_threshold: float = 0.70,
    ):
        self.embedder = embedder or LocalSemanticEmbeddingProvider()
        self.semantic_threshold = semantic_threshold
        self.lexical_threshold = lexical_threshold

    def extract_intent(
        self,
        query: str,
        gap: Optional[InformationGap] = None,
        objective: Optional[str] = None,
    ) -> QueryIntent:
        """Extract multi-layer structured intent from query string and contextual metadata."""
        norm_text = query.strip().lower()
        tokens = set(re.findall(r"[a-z0-9#\-_]+", norm_text))
        stopwords = {"the", "a", "an", "of", "and", "or", "in", "to", "for", "is", "was", "are", "on", "at", "by", "has"}
        meaningful = {t for t in tokens if t not in stopwords}

        # Operational Identifiers
        identifiers = set(re.findall(r"(?:cr|inc|rfc|req|pr|issue|bug)-?\d+|\b\d{2,}\b|#\d+", norm_text, re.IGNORECASE))
        identifiers = {i.upper().replace("#", "") for i in identifiers}

        # Operation / Predicate
        op = InvestigativeOperation.GENERAL_QUERY
        for op_type, lexicon in OPERATION_LEXICON.items():
            if any(term in norm_text for term in lexicon):
                op = op_type
                break

        # Target Entity detection
        entity: Optional[str] = None
        if gap and gap.target_entity:
            entity = gap.target_entity.upper()
        else:
            # Fallback regex extraction from query
            entity_matches = re.findall(
                r"\b(cab|change advisory board|payment gateway|checkout service|redis|kafka|auth|phoenix|postgres|database)\b",
                norm_text,
                re.IGNORECASE,
            )
            if entity_matches:
                raw_ent = entity_matches[0].lower()
                # Normalize canonical entity
                if "cab" in raw_ent or "change" in raw_ent:
                    entity = "CAB"
                elif "payment" in raw_ent or "checkout" in raw_ent:
                    entity = "PAYMENT_GATEWAY"
                elif "phoenix" in raw_ent:
                    entity = "PHOENIX"
                else:
                    entity = raw_ent.upper()

        # Temporal Scope
        temporal: Optional[str] = None
        temp_matches = re.findall(r"\b(tonight|tomorrow|today|friday|monday|weekend|utc|\d{4}-\d{2}-\d{2})\b", norm_text)
        if temp_matches:
            temporal = temp_matches[0].upper()

        return QueryIntent(
            raw_query=query,
            target_entity=entity,
            target_gap_id=gap.gap_id if gap else None,
            operation=op,
            identifiers=identifiers,
            temporal_scope=temporal,
            semantic_text=norm_text,
            normalized_tokens=meaningful,
        )

    def are_intents_compatible_for_dedup(
        self, intent_candidate: QueryIntent, intent_history: QueryIntent
    ) -> Tuple[bool, Optional[str]]:
        """
        Verify contextual compatibility.
        Queries that share high topic similarity but represent different investigative
        operations, entities, or ticket IDs must NEVER be falsely deduplicated.
        """
        # 1. Operational Identifiers: If both have IDs and they differ (e.g. CR-88 vs CR-89) -> NOT duplicate
        if intent_candidate.identifiers and intent_history.identifiers:
            if not intent_candidate.identifiers.intersection(intent_history.identifiers):
                return False, f"Different operational identifiers: {intent_candidate.identifiers} vs {intent_history.identifiers}"

        # 2. Target Entities: If both specify entities and they differ -> NOT duplicate
        if intent_candidate.target_entity and intent_history.target_entity:
            if intent_candidate.target_entity != intent_history.target_entity:
                return False, f"Different target entities: {intent_candidate.target_entity} vs {intent_history.target_entity}"

        # 3. Conflicting Operations on same entity:
        # e.g., 'Was CR-88 approved?' vs 'Was CR-88 executed successfully?' or 'approved' vs 'rolled back'
        opposing_operations = {
            (InvestigativeOperation.APPROVAL, InvestigativeOperation.EXECUTION),
            (InvestigativeOperation.APPROVAL, InvestigativeOperation.ROLLBACK),
            (InvestigativeOperation.EXECUTION, InvestigativeOperation.ROLLBACK),
            (InvestigativeOperation.APPROVAL, InvestigativeOperation.REJECTION),
            (InvestigativeOperation.BACKUP, InvestigativeOperation.ROLLBACK),
            (InvestigativeOperation.BACKUP, InvestigativeOperation.DELETION),
            (InvestigativeOperation.EXECUTION, InvestigativeOperation.DELETION),
            (InvestigativeOperation.APPROVAL, InvestigativeOperation.DELETION),
        }
        cand_op = intent_candidate.operation
        hist_op = intent_history.operation
        if cand_op != InvestigativeOperation.GENERAL_QUERY and hist_op != InvestigativeOperation.GENERAL_QUERY:
            if cand_op != hist_op:
                pair = (cand_op, hist_op)
                rev_pair = (hist_op, cand_op)
                if pair in opposing_operations or rev_pair in opposing_operations:
                    return False, f"Distinct investigative operations: {cand_op.value} vs {hist_op.value}"

        return True, None

    def is_semantically_duplicate(
        self,
        candidate_query: str,
        historical_query: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> SemanticDeduplicationResult:
        """
        Evaluate if candidate query is semantically duplicate with a historical query.
        Returns a rich SemanticDeduplicationResult with complete audit provenance.
        """
        start_time = time.perf_counter()
        gap = context.get("gap") if context else None
        objective = context.get("objective") if context else None

        # 1. Lexical fast gate: Exact string match
        if candidate_query.strip().lower() == historical_query.strip().lower():
            return SemanticDeduplicationResult(
                is_duplicate=True,
                similarity_score=1.0,
                threshold=self.lexical_threshold,
                comparison_query=historical_query,
                contextual_compatibility=True,
                rejection_reason="Exact lexical query match",
                provenance={"method": "EXACT_LEXICAL", "duration_ms": (time.perf_counter() - start_time) * 1000},
            )

        # Extract Intents
        intent_cand = self.extract_intent(candidate_query, gap=gap, objective=objective)
        intent_hist = self.extract_intent(historical_query, gap=gap, objective=objective)

        # 2. Lexical Jaccard check on normalized tokens
        inter = len(intent_cand.normalized_tokens.intersection(intent_hist.normalized_tokens))
        union = len(intent_cand.normalized_tokens.union(intent_hist.normalized_tokens))
        jaccard = inter / union if union > 0 else 0.0

        if jaccard >= self.lexical_threshold:
            # Check intent compatibility even for high Jaccard (e.g. CR-88 vs CR-89)
            compat, reason = self.are_intents_compatible_for_dedup(intent_cand, intent_hist)
            if compat:
                return SemanticDeduplicationResult(
                    is_duplicate=True,
                    similarity_score=jaccard,
                    threshold=self.lexical_threshold,
                    comparison_query=historical_query,
                    contextual_compatibility=True,
                    rejection_reason=f"Lexical Jaccard token overlap ({jaccard:.2f})",
                    provenance={"method": "LEXICAL_JACCARD", "jaccard": jaccard, "duration_ms": (time.perf_counter() - start_time) * 1000},
                )
            else:
                return SemanticDeduplicationResult(
                    is_duplicate=False,
                    similarity_score=jaccard,
                    threshold=self.lexical_threshold,
                    comparison_query=historical_query,
                    contextual_compatibility=False,
                    rejection_reason=f"High lexical overlap overridden by intent incompatibility: {reason}",
                    provenance={"method": "LEXICAL_INCOMPATIBLE", "incompatibility": reason},
                )

        # 3. Contextual Compatibility Check before expensive embedding
        compat, reason = self.are_intents_compatible_for_dedup(intent_cand, intent_hist)
        if not compat:
            return SemanticDeduplicationResult(
                is_duplicate=False,
                similarity_score=0.0,
                threshold=self.semantic_threshold,
                comparison_query=historical_query,
                contextual_compatibility=False,
                rejection_reason=f"Incompatible intent: {reason}",
                provenance={"method": "INTENT_FILTERED", "reason": reason},
            )

        # 4. Dense Semantic Embedding Comparison
        vec_cand = self.embedder.embed(candidate_query)
        vec_hist = self.embedder.embed(historical_query)
        cosine_sim = self.embedder.similarity(vec_cand, vec_hist)

        is_dup = cosine_sim >= self.semantic_threshold
        duration_ms = (time.perf_counter() - start_time) * 1000

        rejection = None
        if is_dup:
            rejection = f"Semantic paraphrase duplicate (cosine similarity: {cosine_sim:.2f} >= {self.semantic_threshold:.2f})"

        return SemanticDeduplicationResult(
            is_duplicate=is_dup,
            similarity_score=cosine_sim,
            threshold=self.semantic_threshold,
            comparison_query=historical_query,
            contextual_compatibility=True,
            rejection_reason=rejection,
            provenance={
                "method": "SEMANTIC_EMBEDDING",
                "cosine_similarity": cosine_sim,
                "threshold": self.semantic_threshold,
                "duration_ms": duration_ms,
                "candidate_intent": intent_cand.model_dump(),
                "history_intent": intent_hist.model_dump(),
            },
        )

    def check_duplicate(
        self,
        candidate_query: str,
        query_history: Set[str],
        context: Optional[Dict[str, Any]] = None,
    ) -> SemanticDeduplicationResult:
        """
        Check candidate query against all queries in query_history.
        Returns the highest-scoring match result.
        """
        best_result: Optional[SemanticDeduplicationResult] = None
        highest_sim = -1.0

        for hist_q in query_history:
            res = self.is_semantically_duplicate(candidate_query, hist_q, context=context)
            if res.is_duplicate:
                return res  # Short circuit on first verified duplicate

            if res.similarity_score > highest_sim:
                highest_sim = res.similarity_score
                best_result = res

        if best_result is not None:
            return best_result

        return SemanticDeduplicationResult(
            is_duplicate=False,
            similarity_score=0.0,
            threshold=self.semantic_threshold,
            comparison_query=None,
            contextual_compatibility=True,
            rejection_reason=None,
            provenance={"history_size": len(query_history)},
        )
