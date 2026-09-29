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
    "wont", "dont", "doesnt", "isnt", "arent", "wasnt", "werent", "disabled", "reverted", "rejected", "shutdown",
    "terminated", "denied", "prohibited", "failed", "unapproved", "disallowed", "decommissioned", "inactive", "stopped"
}

GRAMMATICAL_NEGATION: Set[str] = {
    "not", "never", "no", "neither", "nor", "without", "none", "cannot", "cant",
    "wont", "dont", "doesnt", "isnt", "arent", "wasnt", "werent"
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

# Domain-agnostic set of common English sentence starters and discourse connectives
ENGLISH_COMMON_STARTERS: Set[str] = {
    "Verified", "The", "This", "That", "These", "Those", "All", "Every", "Each", "Both",
    "Our", "We", "Users", "System", "Service", "Evidence", "Investigation", "Note",
    "Target", "Confirmed", "Reported", "According", "When", "While", "Where", "After",
    "Before", "Since", "Because", "Although", "If", "Then", "In", "On", "At", "From",
    "To", "For", "With", "By", "Under", "Over", "However", "Therefore", "Moreover",
    "Furthermore", "Additionally", "Meanwhile", "Currently", "Specifically", "Notably",
    "Overall", "Finally", "Initially", "Previously", "Historically", "None", "Some",
    "Any", "Many", "Most"
}

# Material coordinating and subordinating conjunctions and delimiters for clause boundary decomposition
CLAUSE_SPLIT_PATTERN = re.compile(
    r"(?:"
    r",?\s*\b(?:and|but|while|whereas|although|however|yet|because|since|moreover|furthermore|plus|therefore|nevertheless|despite|also)\b"
    r"|[,;:\u2014\u2013\.]+"
    r"|--+"
    r"|,?\s*\bwith\b"
    r")\s*",
    re.IGNORECASE,
)


class EntailmentVerifier:
    """
    Pure deterministic semantic entailment and veracity verifier.
    Enforces that candidate claims cannot misrepresent admitted evidence.
    Zero neural model dependencies; deterministic sub-millisecond execution.
    """

    @classmethod
    def verify_claim_entailment(
        cls,
        claim: Claim,
        evidence: Evidence,
        admitted_citation_indices: Optional[Set[int]] = None,
    ) -> Tuple[bool, Optional[str]]:
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
        stmt_neg = stmt_words & NEGATION_TOKENS
        content_neg = content_words & NEGATION_TOKENS

        # 1. VERBATIM ANCHOR GROUNDING & PREFIX/SUFFIX NEGATION CHECK
        if claim.verbatim_anchor:
            anchor = claim.verbatim_anchor.strip()
            anchor_norm = " ".join(anchor.split())
            content_norm = " ".join(content.split())
            safe_content_norm = " ".join(redact_sensitive_text(content).split())
            if anchor_norm not in content_norm and anchor_norm not in safe_content_norm:
                return False, f"Verbatim anchor '{anchor[:40]}...' not found in evidence {evidence.evidence_id}"

            # Prefix & Suffix Negation Inspection
            idx = content_lower.find(anchor.lower())
            if idx != -1:
                # Inspect prefix immediately preceding the anchor in the evidence
                prefix = content_lower[max(0, idx - 40):idx]
                prefix_tokens = set(re.findall(r"\b[a-z]+\b", prefix))
                prefix_neg = prefix_tokens & {"not", "never", "no", "without", "neither", "none"}
                stmt_neg_local = stmt_words & {"not", "never", "no", "without", "neither", "none"}
                if prefix_neg and not stmt_neg_local:
                    return False, f"Anchor prefix negation dropped: evidence specifies '{' '.join(prefix_neg)}' before anchor"

                # Inspect suffix in the proposition sentence following the anchor in evidence
                idx_end = idx + len(anchor)
                suffix_window = content_lower[idx_end:idx_end + 120]
                neg_suffix_targets = re.findall(
                    r"\b(?:"
                    r"not|never|no|without|neither|"
                    r"rather\s+than|instead\s+of|as\s+opposed\s+to|in\s+preference\s+to|other\s+than|"
                    r"excluding|except\s+for|except|avoids?|avoiding"
                    r")\s+(?:the\s+|a\s+|an\s+)?([a-zA-Z0-9_\-]+)",
                    suffix_window
                )
                for neg_tgt in neg_suffix_targets:
                    if neg_tgt in statement_lower and not stmt_neg_local:
                        return False, f"Polarity mismatch: claim affirms target '{neg_tgt}' explicitly negated or excluded in evidence"

        # 2. NUMERICAL & METRIC FIDELITY CHECK
        stmt_numbers = set(re.findall(r"\b\d+(?:\.\d+)?\b", statement))
        ev_search_space = f"{content} {evidence.source_id} {evidence.uri or ''} {evidence.start_offset} {evidence.end_offset}"
        ev_numbers = set(re.findall(r"\b\d+(?:\.\d+)?\b", ev_search_space))
        
        # Filter out common structural ordinals like "claim 1", "step 2", "item 3"
        ordinal_matches = set(re.findall(r"\b(?:claim|item|step|part|fact|section)\s+(\d+)\b", statement_lower))
        
        # Citation markers:
        # A bracketed number [N] is only treated as a citation marker if:
        # 1. Syntactically: It appears in citation reference position (preceding punctuation, bracket, or end-of-string),
        #    NOT qualifying a noun (e.g. '[20] instances' is an inline metric quantifier, not a citation marker).
        # 2. Contextually: N corresponds to a valid admitted citation marker index in the investigation.
        max_valid_cit = len(claim.evidence_ids) if claim.evidence_ids else 1
        valid_cit_set = admitted_citation_indices if admitted_citation_indices is not None else set(range(1, max_valid_cit + 1))
        
        bracket_citations = set()
        for m in re.finditer(r"\[(\d+)\](?=\s*(?:[,.;:!?\)\]]|$))", statement):
            num_str = m.group(1)
            if int(num_str) in valid_cit_set:
                bracket_citations.add(num_str)

        stmt_numbers = {n for n in stmt_numbers if n not in ordinal_matches and n not in bracket_citations}
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
        meta_reporting = {
            "verified", "confirmed", "observed", "reported", "proven", "shows", 
            "found", "noted", "stated", "finding", "statement", "claim", 
            "assertion", "evidence", "record"
        }
        ev_text_space = f"{content_lower} {evidence.source_id.lower()} {evidence.uri.lower() if evidence.uri else ''} {evidence.source_path.lower() if evidence.source_path else ''}"
        ev_text_words = set(re.findall(r"\b[a-z]+\b", ev_text_space))
        clauses = [c.strip() for c in CLAUSE_SPLIT_PATTERN.split(statement) if c.strip()]
        for clause in clauses:
            clause_content_words = [w for w in re.findall(r"\b[a-z]{3,}\b", clause.lower()) if w not in STOPWORDS and w not in meta_reporting]
            if len(clause_content_words) >= 2:
                # Word match with stem prefix fallback (e.g. rejection -> rejected)
                in_content_words = [
                    w for w in clause_content_words
                    if w in ev_text_space
                    or (w in POSITIVE_ASSERTION_TOKENS and not content_neg)
                    or any(
                        (cw.startswith(w[:4]) or w.startswith(cw[:4]))
                        for cw in ev_text_words if len(w) >= 4 and len(cw) >= 4
                    )
                ]
                coverage = len(in_content_words) / len(clause_content_words)
                min_coverage = 0.70 if len(clause_content_words) <= 3 else 0.50
                if coverage < min_coverage:
                    unsupported_words = [w for w in clause_content_words if w not in in_content_words]
                    return False, f"Unsupported compound clause: '{clause}' has insufficient grounding ({coverage:.0%}) in evidence (unsupported words: {unsupported_words})"

        # 5. POLARITY & NEGATION INVERSION CHECK
        stmt_neg = stmt_words & NEGATION_TOKENS
        content_neg = content_words & NEGATION_TOKENS

        # Case A: Statement asserts negation/denial when evidence strictly contains positive assertions and zero negation
        if stmt_neg and not content_neg:
            content_pos = content_words & POSITIVE_ASSERTION_TOKENS
            if content_pos:
                return False, f"Polarity mismatch: claim introduces negation {stmt_neg} on positively asserted evidence"

        # Case B: Evidence asserts explicit negation, but statement asserts positive state without negative qualifiers
        stmt_gram_neg = stmt_words & GRAMMATICAL_NEGATION
        ev_gram_neg = content_words & GRAMMATICAL_NEGATION

        if content_neg and not stmt_neg:
            critical_ev_neg = content_neg & {"not", "never", "no", "without", "rejected", "disabled", "reverted", "shutdown", "terminated", "denied", "failed", "unapproved"}
            if critical_ev_neg:
                # Check 1: fixed positive tokens
                stmt_pos = stmt_words & POSITIVE_ASSERTION_TOKENS
                if stmt_pos:
                    return False, f"Polarity mismatch: claim asserts positive state {stmt_pos} on negative/reverted evidence {critical_ev_neg}"

        # Case C: Proposition-level predicate or target negation/exclusion reversal
        if not stmt_gram_neg:
            # 1. Negated predicates (e.g. 'does not send', 'never connects', 'without automated failover', 'avoids Tokyo')
            negated_predicates = re.findall(
                r"\b(?:"
                r"does\s+not|do\s+not|did\s+not|is\s+not|are\s+not|was\s+not|were\s+not|cannot|cant|wont|never|not|without|"
                r"avoids?|avoiding|refuses?\s+to|fails?\s+to"
                r")\s+([a-z]{3,})\b",
                content_lower,
            )
            for pred in negated_predicates:
                if pred in stmt_words or any(sw.startswith(pred[:4]) for sw in stmt_words if len(pred) >= 4):
                    return False, f"Polarity mismatch: claim affirms predicate '{pred}' which is negated in evidence"

            # 2. Negated or excluded targets/destinations (e.g. 'not Tokyo', 'rather than Tokyo', 'instead of Tokyo', 'except Tokyo', 'avoids Tokyo')
            excluded_targets = re.findall(
                r"\b(?:"
                r"not|never|no|without|neither|"
                r"rather\s+than|instead\s+of|as\s+opposed\s+to|in\s+preference\s+to|other\s+than|"
                r"excluding|except\s+for|except|avoids?|avoiding"
                r")\s+(?:the\s+|a\s+|an\s+)?([a-zA-Z0-9_\-]+)",
                content_lower,
            )
            for tgt in excluded_targets:
                if tgt in statement_lower:
                    return False, f"Polarity mismatch: claim affirms target '{tgt}' explicitly negated or excluded in evidence"

        # Antonym opposition check (e.g. vulnerable vs secure, offline vs online)
        for set_a, set_b in OPPOSING_ANTONYMS:
            if (stmt_words & set_a) and (content_words & set_b) and not (content_words & set_a):
                return False, f"Semantic contradiction: claim asserts {stmt_words & set_a} while evidence asserts {content_words & set_b}"
            if (stmt_words & set_b) and (content_words & set_a) and not (content_words & set_b):
                return False, f"Semantic contradiction: claim asserts {stmt_words & set_b} while evidence asserts {content_words & set_a}"

        # 6. ENTITY PRESERVATION & LOCAL CO-OCCURRENCE CHECK
        ev_tokens = set(re.findall(r"\b[A-Za-z0-9]+(?:[\-_][A-Za-z0-9]+)+\b|\b[A-Z][a-zA-Z0-9_\-]{2,}\b", content)) - ENGLISH_COMMON_STARTERS
        matched_entities = {e for e in ev_tokens if e.lower() in statement_lower}

        ev_entity_space = f"{content} {evidence.source_id} {evidence.uri or ''} {evidence.source_path or ''}"
        
        # Structural entities (CamelCase, digits, hyphens) anywhere in statement
        structural_entities = set(re.findall(
            r"\b(?:[a-z0-9]+[A-Z][a-zA-Z0-9]*|[A-Z][a-z0-9]+[A-Z][a-zA-Z0-9]*|[A-Za-z]+[0-9]+|[0-9]+[A-Za-z]+|[A-Za-z0-9]+(?:[-_][A-Za-z0-9]+)+)\b",
            statement
        ))
        
        # Capitalized proper tokens (excluding common English starters)
        all_capitalized = set(re.findall(r"\b[A-Z][a-zA-Z0-9_\-]{2,}\b", statement)) - ENGLISH_COMMON_STARTERS
        
        candidate_entities = structural_entities.union(all_capitalized)
        unsupported_entities = {e for e in candidate_entities if e.lower() not in ev_entity_space.lower()}
        
        # Strict Single Entity Invariant: Even ONE unsupported entity fails verification
        if unsupported_entities:
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

