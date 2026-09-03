"""
ORACLE Semantic Entailment & Veracity Engine (Brick 4.2 Remediation)
===================================================================
Provides deterministic semantic entailment verification:
1. Verbatim Anchor Grounding with Prefix-Aware Negation Alignment.
2. Numerical & Metric Invariance.
3. Scope & Environment Qualifier Preservation (production vs staging/dev).
4. Clause Decomposition & Material Grounding (compound statement validation).
5. Polarity & Antonym Symmetry.
6. Local Sentence-Level Entity-Metric Co-occurrence.

Strictly domain-agnostic and provider-neutral.
"""

import re
from typing import List, Optional, Set, Tuple
from backend.core.security import redact_sensitive_text
from backend.evidence.models import Evidence
from backend.synthesis.models import Claim

# Standard negative polarity tokens
NEGATION_TOKENS: Set[str] = {
    "not", "never", "no", "neither", "nor", "without", "none", "cannot", "cant",
    "wont", "dont", "isnt", "arent", "disabled", "reverted", "rejected", "shutdown",
    "terminated", "denied", "prohibited", "failed", "unencrypted", "insecure",
    "unapproved", "disallowed", "decommissioned", "inactive", "stopped"
}

POSITIVE_ASSERTION_TOKENS: Set[str] = {
    "enforces", "enforced", "active", "deployed", "running",
    "enabled", "approved", "allowed", "permitted", "operational",
    "required", "mandatory", "secure", "encrypted"
}

OPPOSING_ANTONYMS: List[Tuple[Set[str], Set[str]]] = [
    ({"vulnerable", "insecure", "compromised", "breached"}, {"secure", "safe", "protected", "hardened"}),
    ({"offline", "down", "unreachable"}, {"online", "up", "reachable"}),
    ({"failed", "aborted", "crashed"}, {"succeeded", "passed", "stable"}),
    ({"unencrypted", "plaintext"}, {"encrypted", "tls", "mtls"}),
]

SCOPE_QUALIFIERS: Set[str] = {
    "production", "prod", "staging", "stage", "development", "dev",
    "testing", "test", "local", "canary", "sandbox", "internal", "external", "preview", "qa", "uat"
}

RESTRICTED_SCOPES: Set[str] = {
    "staging", "stage", "development", "dev", "testing", "test", "local", "canary", "sandbox", "preview", "qa", "uat"
}

STOPWORDS: Set[str] = {
    "is", "are", "was", "were", "be", "been", "being", "the", "a", "an",
    "in", "on", "at", "to", "for", "with", "by", "about", "against", "between",
    "into", "through", "during", "before", "after", "above", "below", "of", "from"
}


class EntailmentVerifier:
    """
    Pure deterministic semantic entailment and veracity verifier.
    Enforces that candidate claims cannot misrepresent admitted evidence.
    Zero neural model dependencies; deterministic sub-millisecond execution.
    """

    @classmethod
    def verify_claim_entailment(cls, claim: Claim, evidence: Evidence) -> Tuple[bool, Optional[str]]:
        """
        Validates that a claim is faithfully grounded and entailed by the cited Evidence object.
        Returns:
            (True, None) if the claim is validly entailed.
            (False, failure_reason) if the claim distorts, inverts, or fabricates facts.
        """
        statement = claim.statement.strip()
        content = evidence.content.strip()
        statement_lower = statement.lower()
        content_lower = content.lower()

        stmt_words = set(re.findall(r"\b[a-z]+\b", statement_lower))
        content_words = set(re.findall(r"\b[a-z]+\b", content_lower))

        # 1. VERBATIM ANCHOR GROUNDING & PREFIX NEGATION CHECK
        if claim.verbatim_anchor:
            anchor = claim.verbatim_anchor.strip()
            anchor_norm = " ".join(anchor.split())
            content_norm = " ".join(content.split())
            safe_content_norm = " ".join(redact_sensitive_text(content).split())
            if anchor_norm not in content_norm and anchor_norm not in safe_content_norm:
                return False, f"Verbatim anchor '{anchor[:40]}...' not found in evidence {evidence.evidence_id}"

            # Prefix Negation Inspection: Locate anchor in evidence content
            idx = content_lower.find(anchor.lower())
            if idx != -1:
                # Inspect the 5 words immediately preceding the anchor in the evidence
                prefix = content_lower[max(0, idx - 40):idx]
                prefix_tokens = set(re.findall(r"\b[a-z]+\b", prefix))
                prefix_neg = prefix_tokens & {"not", "never", "no", "without", "neither", "none"}
                stmt_neg_local = stmt_words & {"not", "never", "no", "without", "neither", "none"}
                if prefix_neg and not stmt_neg_local:
                    return False, f"Anchor prefix negation dropped: evidence specifies '{' '.join(prefix_neg)}' before anchor"

        # 2. NUMERICAL & METRIC FIDELITY CHECK
        stmt_numbers = set(re.findall(r"\b\d+(?:\.\d+)?\b", statement))
        ev_search_space = f"{content} {evidence.source_id} {evidence.uri or ''} {evidence.start_offset} {evidence.end_offset}"
        ev_numbers = set(re.findall(r"\b\d+(?:\.\d+)?\b", ev_search_space))
        
        # Filter out common structural ordinals like "[1]", "[2]", "claim 1", "step 2"
        ordinal_matches = set(re.findall(r"\b(?:claim|item|step|part|fact|section)\s+(\d+)\b", statement_lower))
        bracket_matches = set(re.findall(r"\[(\d+)\]", statement))
        stmt_numbers = {n for n in stmt_numbers if n not in ordinal_matches and n not in bracket_matches}
        unsupported_numbers = stmt_numbers - ev_numbers
        if unsupported_numbers:
            return False, f"Claim asserts unsupported numerical quantities or ports: {unsupported_numbers}"

        # 3. SCOPE & ENVIRONMENT QUALIFIER PRESERVATION
        stmt_scopes = stmt_words & SCOPE_QUALIFIERS
        content_scopes = content_words & SCOPE_QUALIFIERS

        # Rule A: Claim cannot assert a scope qualifier completely absent from evidence
        unsupported_scopes = stmt_scopes - content_scopes
        if unsupported_scopes:
            return False, f"Scope mismatch: claim asserts scope {unsupported_scopes} absent from evidence"

        # Rule B: Evidence restricted to non-production cannot be promoted without scope qualifier
        ev_restricted = content_scopes & RESTRICTED_SCOPES
        if ev_restricted and not stmt_scopes:
            return False, f"Scope drop: evidence restricts assertion to {ev_restricted}, but claim drops scope qualifier"

        # 4. COMPOUND STATEMENT & MATERIAL CLAUSE DECOMPOSITION
        meta_reporting = {"verified", "confirmed", "observed", "reported", "proven", "shows", "found", "noted", "stated", "finding"}
        clauses = [c.strip() for c in re.split(r"\b(?:and|but|while|whereas|although|furthermore|moreover)\b|[;\.]", statement, flags=re.IGNORECASE) if c.strip()]
        for clause in clauses:
            clause_content_words = [w for w in re.findall(r"\b[a-z]{3,}\b", clause.lower()) if w not in STOPWORDS and w not in meta_reporting]
            if len(clause_content_words) >= 2:
                # Word match with stem prefix fallback (e.g. rejection -> rejected)
                in_content_words = [
                    w for w in clause_content_words
                    if w in content_lower or any(cw.startswith(w[:5]) for cw in content_words if len(w) >= 5)
                ]
                coverage = len(in_content_words) / len(clause_content_words)
                if coverage < 0.5:
                    return False, f"Unsupported compound clause: '{clause}' has insufficient grounding ({coverage:.0%}) in evidence"

        # 5. POLARITY & NEGATION INVERSION CHECK
        stmt_neg = stmt_words & NEGATION_TOKENS
        content_neg = content_words & NEGATION_TOKENS

        # Case A: Statement asserts negation/denial when evidence strictly contains positive assertions and zero negation
        if stmt_neg and not content_neg:
            content_pos = content_words & POSITIVE_ASSERTION_TOKENS
            if content_pos:
                return False, f"Polarity mismatch: claim introduces negation {stmt_neg} on positively asserted evidence"

        # Case B: Evidence asserts explicit negation, but statement asserts positive state without negative qualifiers
        if content_neg and not stmt_neg:
            critical_ev_neg = content_neg & {"not", "never", "no", "without", "rejected", "disabled", "reverted", "shutdown", "terminated", "denied", "failed", "unapproved"}
            if critical_ev_neg:
                stmt_pos = stmt_words & POSITIVE_ASSERTION_TOKENS
                if stmt_pos:
                    return False, f"Polarity mismatch: claim asserts positive state {stmt_pos} on negative/reverted evidence {critical_ev_neg}"

        # Antonym opposition check (e.g. vulnerable vs secure, offline vs online)
        for set_a, set_b in OPPOSING_ANTONYMS:
            if (stmt_words & set_a) and (content_words & set_b) and not (content_words & set_a):
                return False, f"Semantic contradiction: claim asserts {stmt_words & set_a} while evidence asserts {content_words & set_b}"
            if (stmt_words & set_b) and (content_words & set_a) and not (content_words & set_b):
                return False, f"Semantic contradiction: claim asserts {stmt_words & set_b} while evidence asserts {content_words & set_a}"

        # 6. ENTITY PRESERVATION & LOCAL CO-OCCURRENCE CHECK
        common_starters = {
            "Verified", "The", "This", "All", "Every", "Our", "Users", "System", "Service", "Evidence", "Investigation", "Note", "Target"
        }
        stmt_entities = set(re.findall(r"\b[a-zA-Z0-9_\-]{2,}\b", statement))
        ev_tokens = set(re.findall(r"\b[A-Za-z0-9]+(?:[\-_][A-Za-z0-9]+)+\b|\b[A-Z][a-zA-Z0-9_\-]{2,}\b", content)) - common_starters
        matched_entities = {e for e in ev_tokens if e.lower() in statement_lower}

        ev_entity_space = f"{content} {evidence.source_id} {evidence.uri or ''} {evidence.source_path or ''}"
        unsupported_entities = {e for e in (set(re.findall(r"\b[A-Z][a-zA-Z0-9_\-]{2,}\b", statement)) - common_starters) if e.lower() not in ev_entity_space.lower()}
        
        if unsupported_entities and len(unsupported_entities) > 1:
            return False, f"Claim asserts unsupported foreign entities: {unsupported_entities}"

        # Local sentence-level co-occurrence for entity-metric binding
        if matched_entities and stmt_numbers and not claim.verbatim_anchor:
            sentences = [s.strip() for s in re.split(r"[\.\n;]", content) if s.strip()]
            if len(sentences) > 1:
                cooccurring = any(
                    any(e.lower() in s.lower() for e in matched_entities) and any(n in s for n in stmt_numbers)
                    for s in sentences
                )
                if not cooccurring:
                    return False, f"Entity-metric cross-attribution mismatch: {matched_entities} and {stmt_numbers} do not co-occur in any evidence sentence"

        return True, None
