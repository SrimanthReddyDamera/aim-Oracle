"""
ORACLE Semantic Polarity & Opposition Engine (Brick 3.5A)
Provides a clean, domain-agnostic abstraction for representing claim polarity,
operational state, and semantic opposition between claims across documents.

Replaces brittle ad-hoc keyword whitelists with structured opposition domains:
  - DECISION_APPROVAL:   APPROVED / ACCEPTED  <--->  REJECTED / DENIED / DISAPPROVED / VETOED
  - LIFECYCLE_STATUS:    ACTIVE / RUNNING     <--->  CANCELLED / DECOMMISSIONED / REVOKED / TERMINATED
  - DEPLOYMENT_STATE:    DEPLOYED / APPLIED   <--->  ROLLED_BACK / ROLLBACK / ABORTED
  - VALIDITY_COMPLIANCE: VALID / COMPLIANT    <--->  INVALID / NON_COMPLIANT / CORRUPT
  - OPERATIONAL_TOGGLE:  ENABLED / ONLINE     <--->  DISABLED / OFFLINE
  - EXECUTION_OUTCOME:   PASSED / SUCCEEDED   <--->  FAILED / CRASHED / OUTAGE
"""

from enum import Enum
import re
from typing import Dict, List, Optional, Set, Tuple
from pydantic import BaseModel, Field


class Polarity(str, Enum):
    POSITIVE = "POSITIVE"
    NEGATIVE = "NEGATIVE"
    NEUTRAL  = "NEUTRAL"


class OppositionDomain(str, Enum):
    DECISION_APPROVAL   = "DECISION_APPROVAL"   # Governance, approval, authority disposition
    LIFECYCLE_STATUS    = "LIFECYCLE_STATUS"    # Active production status vs cancellation
    DEPLOYMENT_STATE    = "DEPLOYMENT_STATE"    # Deployment execution vs rollback
    VALIDITY_COMPLIANCE = "VALIDITY_COMPLIANCE" # Policy/schema/config validity
    OPERATIONAL_TOGGLE  = "OPERATIONAL_TOGGLE"  # Feature/network toggle state
    EXECUTION_OUTCOME   = "EXECUTION_OUTCOME"   # Health, build, test, runtime outcome


class PolarityMarker(BaseModel):
    """Represents a discrete semantic polarity token within a domain."""
    token: str
    normalized: str
    domain: OppositionDomain
    polarity: Polarity
    weight: float = 1.0


class OppositionMatch(BaseModel):
    """Represents detected semantic opposition between two claims or documents."""
    domain: OppositionDomain
    positive_term: str
    negative_term: str
    basis: str
    confidence: float = 1.0


# Domain lexicon mapping normalized root terms to polarity classes
DOMAIN_LEXICON: Dict[OppositionDomain, Dict[Polarity, Set[str]]] = {
    OppositionDomain.DECISION_APPROVAL: {
        Polarity.POSITIVE: {"APPROVED", "APPROVE", "APPROVAL", "ACCEPTED", "ACCEPT", "AUTHORIZED", "AUTHORIZE", "PASSED_CAB", "ENDORSED", "CONFIRMED"},
        Polarity.NEGATIVE: {"REJECTED", "REJECT", "DENIED", "DENY", "DISAPPROVED", "DISAPPROVE", "VETOED", "VETO", "UNAUTHORIZED", "DISALLOWED"},
    },
    OppositionDomain.LIFECYCLE_STATUS: {
        Polarity.POSITIVE: {"ACTIVE", "LIVE", "RUNNING", "OPERATIONAL", "CURRENT", "ACTIVE_PRODUCTION", "HEALTHY", "IN_SERVICE"},
        Polarity.NEGATIVE: {"CANCELLED", "CANCEL", "DECOMMISSIONED", "REVOKED", "REVOKE", "TERMINATED", "OBSOLETE", "DEPRECATED", "SHUTDOWN", "DISCONTINUED"},
    },
    OppositionDomain.DEPLOYMENT_STATE: {
        Polarity.POSITIVE: {"DEPLOYED", "DEPLOY", "APPLIED", "RELEASED", "MIGRATED", "PROMOTED", "INSTALLED", "ROLLED_OUT"},
        Polarity.NEGATIVE: {"ROLLED_BACK", "ROLLBACK", "ABORTED", "ABORT", "REVERTED", "REVERT", "RECALLED", "FAILED_DEPLOYMENT"},
    },
    OppositionDomain.VALIDITY_COMPLIANCE: {
        Polarity.POSITIVE: {"VALID", "VALIDATED", "COMPLIANT", "SATISFIED", "CONFORMANT", "VERIFIED"},
        Polarity.NEGATIVE: {"INVALID", "INVALIDATED", "NON_COMPLIANT", "VIOLATED", "CORRUPT", "UNVERIFIED", "NON_CONFORMANT"},
    },
    OppositionDomain.OPERATIONAL_TOGGLE: {
        Polarity.POSITIVE: {"ENABLED", "ENABLE", "ACTIVATED", "ONLINE", "ACTIVE_TOGGLE", "OPENED"},
        Polarity.NEGATIVE: {"DISABLED", "DISABLE", "DEACTIVATED", "OFFLINE", "BLOCKED_TOGGLE", "CLOSED"},
    },
    OppositionDomain.EXECUTION_OUTCOME: {
        Polarity.POSITIVE: {"PASSED", "PASS", "SUCCEEDED", "SUCCESS", "SUCCESSFUL", "RESOLVED", "OK", "HEALTHY"},
        Polarity.NEGATIVE: {"FAILED", "FAIL", "FAILURE", "CRASHED", "CRASH", "OUTAGE", "BROKEN", "ERROR"},
    },
}


class OppositionEngine:
    """
    Extensible engine for detecting semantic polarity and claim-level opposition.
    """

    def __init__(self, custom_lexicon: Optional[Dict[OppositionDomain, Dict[Polarity, Set[str]]]] = None):
        self.lexicon = custom_lexicon or DOMAIN_LEXICON
        self._token_to_marker: Dict[str, PolarityMarker] = {}
        self._build_index()

    def _build_index(self):
        for domain, pol_map in self.lexicon.items():
            for pol, terms in pol_map.items():
                for term in terms:
                    norm = self.normalize_token(term)
                    self._token_to_marker[norm] = PolarityMarker(
                        token=term,
                        normalized=norm,
                        domain=domain,
                        polarity=pol,
                    )

    @staticmethod
    def normalize_token(token: str) -> str:
        return re.sub(r"[^A-Za-z0-9]", "", token.upper().strip())

    def extract_markers(self, text: str) -> List[PolarityMarker]:
        """Extract all recognized polarity markers from a text segment."""
        tokens = re.findall(r"\b[A-Za-z0-9\_\-]+\b", text.upper())
        markers: List[PolarityMarker] = []
        # Check bigrams first (e.g. ROLLED BACK, NON COMPLIANT, FAILED DEPLOYMENT)
        for i in range(len(tokens) - 1):
            bigram = f"{tokens[i]}_{tokens[i+1]}"
            norm_bi = self.normalize_token(bigram)
            if norm_bi in self._token_to_marker:
                markers.append(self._token_to_marker[norm_bi])
        for raw in tokens:
            norm = self.normalize_token(raw)
            if norm in self._token_to_marker:
                markers.append(self._token_to_marker[norm])
        return markers

    def get_negative_markers(self, text: str) -> List[PolarityMarker]:
        """Extract all negative/opposition markers from a text segment."""
        return [m for m in self.extract_markers(text) if m.polarity == Polarity.NEGATIVE]

    def has_negative_marker(self, text: str, domain: Optional[OppositionDomain] = None) -> bool:
        """Return True if text contains at least one negative marker, optionally restricted to domain."""
        for m in self.extract_markers(text):
            if m.polarity == Polarity.NEGATIVE:
                if domain is None or m.domain == domain:
                    return True
        return False

    def detect_opposition(
        self,
        text_a: str,
        text_b: str,
        target_entity: Optional[str] = None,
    ) -> Optional[OppositionMatch]:
        """
        Evaluate whether text_a and text_b contain opposing polarity markers
        within the same semantic domain.
        """
        markers_a = self.extract_markers(text_a)
        markers_b = self.extract_markers(text_b)

        if not markers_a or not markers_b:
            return None

        # Check for matching domains with opposing polarities
        for ma in markers_a:
            for mb in markers_b:
                if ma.domain == mb.domain:
                    # Positive in A and Negative in B
                    if ma.polarity == Polarity.POSITIVE and mb.polarity == Polarity.NEGATIVE:
                        basis = f"Opposing claims in domain {ma.domain.value}: '{ma.token}' vs '{mb.token}'"
                        if target_entity:
                            basis += f" for entity '{target_entity}'"
                        return OppositionMatch(
                            domain=ma.domain,
                            positive_term=ma.token,
                            negative_term=mb.token,
                            basis=basis,
                            confidence=1.0,
                        )
                    # Negative in A and Positive in B
                    elif ma.polarity == Polarity.NEGATIVE and mb.polarity == Polarity.POSITIVE:
                        basis = f"Opposing claims in domain {ma.domain.value}: '{mb.token}' vs '{ma.token}'"
                        if target_entity:
                            basis += f" for entity '{target_entity}'"
                        return OppositionMatch(
                            domain=ma.domain,
                            positive_term=mb.token,
                            negative_term=ma.token,
                            basis=basis,
                            confidence=1.0,
                        )

        return None
