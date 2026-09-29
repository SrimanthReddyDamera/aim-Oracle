"""
ORACLE Deterministic Entity & Reference Scanner (Brick 3.4 Generic)
Extracts explicit entity references, ticket codes, change requests, and regulations.
Domain-agnostic matching for tickets, change requests, and documents.
"""

import re
from typing import Dict, List, Set, Tuple

from backend.evidence.models import Evidence
from backend.investigation.models import (
    EdgeDerivationType,
    EvidenceEdge,
    RelationshipType,
)
from backend.investigation.temporal_scanner import TemporalConflictScanner

TOKEN_PATTERNS = {
    "DOC_ID": re.compile(r"\b(?:DOC|SPEC|ARCH|RFC|POL)-[A-Z0-9\-]+\b", re.IGNORECASE),
    "INCIDENT": re.compile(r"\b(?:INC|INCIDENT|OUTAGE|ALERT|SEV)-\d+\b", re.IGNORECASE),
    "CHANGE_REQUEST": re.compile(r"\b(?:CR|CHG|RFC|PR|MR)-\d+\b", re.IGNORECASE),
    "REGULATION": re.compile(r"\b(?:REG|COMPLIANCE|SLA|POL|STANDARD)-[A-Z0-9\.]+\b", re.IGNORECASE),
    "VERSION": re.compile(r"\bv\d+\.\d+(?:\.\d+)?\b", re.IGNORECASE),
    "GENERIC_TICKET": re.compile(r"\b[A-Z]{2,10}-\d+\b", re.IGNORECASE),
}

AUTHORITY_DECISION_PATTERN = re.compile(
    r"\b(?:"
    r"(?:(?:change|review|architecture|governance|board|advisory|cab|release)\s+)?decision\s*:\s*(?:rejected|approved|deferred|cancelled|accepted)|"
    r"decision\s+record|"
    r"meeting\s+#\d+\s+decision|"
    r"disposition\s*:\s*(?:rejected|approved|deferred|cancelled|accepted)"
    r")\b",
    re.IGNORECASE,
)
CR_DECISION_PATTERN = AUTHORITY_DECISION_PATTERN


INCIDENT_RESOLUTION_PATTERN = re.compile(
    r"\b(?:"
    r"current\s+production\s+state|"
    r"active\s+production\s+state|"
    r"current\s+operational\s+state|"
    r"active\s+production\s+status|"
    r"active\s+production\s+configuration|"
    r"final\s+resolution"
    r")\b",
    re.IGNORECASE,
)


class EntityScanner:
    """
    Deterministic scanner for tracking cross-chunk references and candidate query tokens.
    Distinguishes proposal/reference mentions from authoritative resolutions.
    """

    @classmethod
    def classify_token(cls, token: str) -> str:
        """Classify entity or reference token into standard operational category."""
        t_up = token.upper().strip()
        for category in ["DOC_ID", "INCIDENT", "CHANGE_REQUEST", "REGULATION", "VERSION"]:
            pattern = TOKEN_PATTERNS[category]
            if pattern.fullmatch(t_up):
                return category
        if re.fullmatch(r"[A-Z]{2,10}-\d+", t_up):
            return "GENERIC_TICKET"
        return "UNKNOWN"

    def extract_references(self, text: str) -> Dict[str, Set[str]]:
        """Extract all operational entity tokens present in the given text."""
        found: Dict[str, Set[str]] = {}
        for category, pattern in TOKEN_PATTERNS.items():
            matches = set(pattern.findall(text))
            if matches:
                found[category] = matches
        return found

    def is_authoritative_resolution(self, token: str, evidence: Evidence) -> bool:
        """
        Check whether a specific chunk provides authoritative resolution/decision
        evidence for the given entity token.
        """
        token_upper = token.upper()
        content = evidence.content
        content_upper = content.upper()
        source_upper = evidence.source_id.upper()
        category = self.classify_token(token_upper)

        # Document code: resolved if this chunk originates from that document
        if category == "DOC_ID" or token_upper.startswith("DOC-"):
            return token_upper in source_upper

        # Change Request / Review ticket: resolved only if chunk contains authoritative decision/disposition
        if category == "CHANGE_REQUEST" or token_upper.startswith("CR-"):
            if token_upper in content_upper or token_upper in source_upper:
                if AUTHORITY_DECISION_PATTERN.search(content) or "REJECTED" in content_upper or "APPROVED" in content_upper:
                    return True
            return False

        # Incident: resolved only if chunk explicitly provides current production state or active operational status
        if category == "INCIDENT" or token_upper.startswith("INC-"):
            if token_upper in content_upper or token_upper in source_upper:
                if (
                    INCIDENT_RESOLUTION_PATTERN.search(content)
                    or "CURRENT PRODUCTION STATE" in content_upper
                ):
                    return True
            return False

        # Regulations: resolved if full section clause is present in the source doc
        if category == "REGULATION" or token_upper.startswith("REG-"):
            if token_upper in content_upper and ("COMPLIANCE" in source_upper or "SLA" in source_upper):
                return True

        return False

    def find_unresolved_references(
        self,
        evidence_dict: Dict[str, Evidence],
    ) -> Set[str]:
        """
        Identify explicit entity tokens referenced in existing chunks that do NOT
        yet have an authoritative resolution/originating chunk present in the evidence set.
        """
        referenced_tokens: Set[str] = set()
        resolved_tokens: Set[str] = set()

        for ev in evidence_dict.values():
            extracted = self.extract_references(ev.content)
            for category in ["INCIDENT", "CHANGE_REQUEST", "DOC_ID"]:
                for token in extracted.get(category, set()):
                    referenced_tokens.add(token.upper())

            # If the source_id itself references an incident or change request, track as referenced
            source_extracted = self.extract_references(ev.source_id)
            for category in ["INCIDENT", "CHANGE_REQUEST"]:
                for token in source_extracted.get(category, set()):
                    referenced_tokens.add(token.upper())

            for category in ["INCIDENT", "CHANGE_REQUEST", "DOC_ID"]:
                for token in extracted.get(category, set()):
                    if self.is_authoritative_resolution(token, ev):
                        resolved_tokens.add(token.upper())

            for category in ["INCIDENT", "CHANGE_REQUEST"]:
                for token in source_extracted.get(category, set()):
                    if self.is_authoritative_resolution(token, ev):
                        resolved_tokens.add(token.upper())

            # Document code is resolved if chunk originates from that document
            for doc_token in source_extracted.get("DOC_ID", set()):
                resolved_tokens.add(doc_token.upper())
            if ev.source_id.upper().startswith("DOC-"):
                resolved_tokens.add(ev.source_id.upper())

        # Unresolved is the set difference of all referenced tokens minus authoritative resolutions
        unresolved = referenced_tokens - resolved_tokens
        return unresolved

    def detect_deterministic_edges(
        self,
        evidence_list: List[Evidence],
    ) -> List[EvidenceEdge]:
        """
        Construct EvidenceEdge relationships for explicit citations between chunks.
        Every edge generated has derived_by = DETERMINISTIC_REFERENCE and confidence = 1.0.
        """
        edges: List[EvidenceEdge] = []
        n = len(evidence_list)

        for i in range(n):
            for j in range(n):
                if i == j:
                    continue
                src = evidence_list[i]
                tgt = evidence_list[j]

                # 1. Direct document code citation
                if tgt.source_id.upper() in src.content.upper():
                    edges.append(
                        EvidenceEdge(
                            source_evidence_id=src.evidence_id,
                            target_evidence_id=tgt.evidence_id,
                            relationship_type=RelationshipType.REFERENCES,
                            basis=f"Source explicitly cites document code '{tgt.source_id}'",
                            derived_by=EdgeDerivationType.DETERMINISTIC_REFERENCE,
                            confidence=1.0,
                        )
                    )

                # 2. Shared operational ticket identifiers
                src_tokens = self.extract_references(src.content)
                tgt_tokens = self.extract_references(tgt.content)

                for category in ["INCIDENT", "CHANGE_REQUEST"]:
                    shared = src_tokens.get(category, set()).intersection(
                        tgt_tokens.get(category, set())
                    )
                    for token in shared:
                        src_opposes = any(term in src.content.upper() for term in ["REJECTED", "CANCELLED", "BLOCKED", "FAILED", "DISAPPROVED"]) or bool(AUTHORITY_DECISION_PATTERN.search(src.content))
                        tgt_asserts_active = any(term in tgt.content.lower() for term in ["proposal", "pull request", "merge", "patch", "deploy", "implement", "request", "upgrade"]) or tgt.source_type in ["github", "jira"]
                        if "SUPERSEDES" in src.content.upper():
                            edges.append(
                                EvidenceEdge(
                                    source_evidence_id=src.evidence_id,
                                    target_evidence_id=tgt.evidence_id,
                                    relationship_type=RelationshipType.SUPERSEDES,
                                    basis=f"Authoritative record explicitly supersedes prior disposition for {token}",
                                    derived_by=EdgeDerivationType.DETERMINISTIC_REFERENCE,
                                    confidence=1.0,
                                )
                            )
                        elif src_opposes and tgt_asserts_active and not any(term in tgt.content.upper() for term in ["REJECTED", "CANCELLED", "BLOCKED"]):
                            edges.append(
                                EvidenceEdge(
                                    source_evidence_id=src.evidence_id,
                                    target_evidence_id=tgt.evidence_id,
                                    relationship_type=RelationshipType.CONTRADICTS,
                                    basis=f"Authoritative decision opposes operational request {token}",
                                    derived_by=EdgeDerivationType.DETERMINISTIC_REFERENCE,
                                    confidence=1.0,
                                )
                            )
                        else:
                            edges.append(
                                EvidenceEdge(
                                    source_evidence_id=src.evidence_id,
                                    target_evidence_id=tgt.evidence_id,
                                    relationship_type=RelationshipType.REFERENCES,
                                    basis=f"Shared operational identifier: {token}",
                                    derived_by=EdgeDerivationType.DETERMINISTIC_REFERENCE,
                                    confidence=1.0,
                                )
                            )

                # 3. Incident Rollback / Operational Reversion superseding Prior Specification
                src_is_rollback = any(term in src.content.lower() for term in ["rollback", "rolled back", "reverted", "decommissioned"]) or bool(INCIDENT_RESOLUTION_PATTERN.search(src.content))
                tgt_is_spec = self.classify_token(tgt.source_id) == "DOC_ID" or any(term in tgt.source_id.lower() for term in ["spec", "arch", "policy", "standard", "design"])
                if src_is_rollback and tgt_is_spec and src.source_id != tgt.source_id:
                    edges.append(
                        EvidenceEdge(
                            source_evidence_id=src.evidence_id,
                            target_evidence_id=tgt.evidence_id,
                            relationship_type=RelationshipType.SUPERSEDES,
                            basis="Operational incident disposition supersedes prior specification",
                            derived_by=EdgeDerivationType.DETERMINISTIC_REFERENCE,
                            confidence=1.0,
                        )
                    )

        # 4. Cross-Provider Temporal Supersession & State Opposition (Brick 4.2)
        temporal_edges = TemporalConflictScanner.detect_temporal_relationships(evidence_list)
        existing_keys = {(e.source_evidence_id, e.target_evidence_id, e.relationship_type) for e in edges}
        for t_edge in temporal_edges:
            key = (t_edge.source_evidence_id, t_edge.target_evidence_id, t_edge.relationship_type)
            if key not in existing_keys:
                edges.append(t_edge)
                existing_keys.add(key)

        return edges
