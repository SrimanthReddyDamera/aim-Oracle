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
    "DOC_ID": re.compile(r"\bDOC-[A-Z0-9\-]+\b", re.IGNORECASE),
    "INCIDENT": re.compile(r"\bINC-\d+\b", re.IGNORECASE),
    "CHANGE_REQUEST": re.compile(r"\bCR-\d+\b", re.IGNORECASE),
    "REGULATION": re.compile(r"\bREG-[A-Z0-9\-]+\b", re.IGNORECASE),
    "VERSION": re.compile(r"\bv\d+\.\d+(?:\.\d+)?\b", re.IGNORECASE),
}

CR_DECISION_PATTERN = re.compile(
    r"\b(?:cab\s+decision\s*:\s*(?:rejected|approved|deferred)|decision\s*:\s*(?:rejected|approved|deferred)|decision\s+record|meeting\s+#\d+\s+decision|disposition\s*:\s*(?:rejected|approved))\b",
    re.IGNORECASE
)


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

        # Document code: resolved if this chunk originates from that document
        if token_upper.startswith("DOC-"):
            return token_upper in evidence.source_id.upper()

        # Change Request: resolved only if chunk contains authoritative decision/disposition
        if token_upper.startswith("CR-"):
            if token_upper in content.upper() or token_upper in evidence.source_id.upper():
                if CR_DECISION_PATTERN.search(content) or "CAB DECISION" in content.upper() or "REJECTED" in content.upper() or "APPROVED" in content.upper():
                    return True
            return False

        # Incident: resolved only if chunk explicitly provides current production state or active operational status
        if token_upper.startswith("INC-"):
            if token_upper in content.upper() or token_upper in evidence.source_id.upper():
                if (
                    INCIDENT_RESOLUTION_PATTERN.search(content)
                    or "CURRENT PRODUCTION STATE" in content.upper()
                ):
                    return True
            return False

        # Regulations: resolved if full section clause is present in the source doc
        if token_upper.startswith("REG-"):
            if token_upper in content.upper() and ("COMPLIANCE" in evidence.source_id.upper() or "SLA" in evidence.source_id.upper()):
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

            # If the source_id itself references an incident or ticket, track as referenced
            for inc in re.findall(r"\bINC-\d+\b", ev.source_id, re.IGNORECASE):
                referenced_tokens.add(inc.upper())
            for cr in re.findall(r"\bCR-\d+\b", ev.source_id, re.IGNORECASE):
                referenced_tokens.add(cr.upper())

            # Check if this chunk resolves any tokens
            for category in ["INCIDENT", "CHANGE_REQUEST", "DOC_ID"]:
                for token in extracted.get(category, set()):
                    if self.is_authoritative_resolution(token, ev):
                        resolved_tokens.add(token.upper())

            # Also check if source_id resolves an incident via authoritative resolution
            for inc in re.findall(r"\bINC-\d+\b", ev.source_id, re.IGNORECASE):
                if self.is_authoritative_resolution(inc, ev):
                    resolved_tokens.add(inc.upper())

            # Document code is resolved if chunk originates from that document
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
                        if "REJECTED" in src.content.upper() and ("re-attempt" in tgt.content.lower() or "emergency" in tgt.content.lower()):
                            edges.append(
                                EvidenceEdge(
                                    source_evidence_id=src.evidence_id,
                                    target_evidence_id=tgt.evidence_id,
                                    relationship_type=RelationshipType.CONTRADICTS,
                                    basis=f"Authoritative decision rejects proposed change request {token}",
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

                # 3. Post-Mortem Rollback superseding Old Specification
                if "rollback" in src.content.lower() and ("arch" in tgt.source_id.lower() or "spec" in tgt.source_id.lower()):
                    edges.append(
                        EvidenceEdge(
                            source_evidence_id=src.evidence_id,
                            target_evidence_id=tgt.evidence_id,
                            relationship_type=RelationshipType.SUPERSEDES,
                            basis="Post-mortem rollback invalidates superseded architecture specification",
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
