"""
ORACLE Cross-Provider Temporal Conflict & Staleness Scanner (Brick 4.2 Remediation)
===================================================================================
Identifies cross-provider state oppositions, temporal ordering, and authority hierarchies.
Resolves directed SUPERSEDES edges when newer, equally or more authoritative evidence
supersedes older evidence. Resolves CONTRADICTS when authority conflicts, timestamps concur,
or timestamps are absent/unresolved.
"""

from datetime import datetime
import re
from typing import Dict, List, Optional, Set, Tuple
from backend.evidence.models import Evidence
from backend.investigation.models import (
    EdgeDerivationType,
    EvidenceEdge,
    RelationshipType,
)

# Standard operational states
POSITIVE_STATES: Set[str] = {
    "active", "deployed", "running", "enabled", "approved", "operational", "completed", "live"
}

NEGATIVE_STATES: Set[str] = {
    "disabled", "reverted", "rejected", "shutdown", "terminated", "failed",
    "decommissioned", "rollback", "rolled back", "inactive", "stopped"
}

# Regex to detect entity mentions (services, components, gateways, clusters, modules)
# Supports hyphenated (auth-gateway) and 2-word space-separated (Billing cluster, Payment gateway) nouns
ENTITY_PATTERN = re.compile(
    r"\b(?:([a-zA-Z0-9\-_]{2,30}?(?:-service|-gateway|-engine|-cluster|-api|-broker|-db|-app))|([a-zA-Z0-9\-_]{2,20}\s+(?:gateway|service|cluster|engine|broker|component|database|module|pipeline|app)))\b",
    re.IGNORECASE
)


class TemporalConflictScanner:
    """
    Scans evidence collections across providers to identify:
    1. SUPERSEDES edges: when a newer document of equal/higher authority supersedes older evidence.
    2. CONTRADICTS edges: when opposing states cannot be resolved temporally or authority conflicts.
    """

    @classmethod
    def _parse_timestamp(cls, ts_str: Optional[str]) -> Optional[datetime]:
        """Parse ISO-8601 or standard timestamp string to datetime."""
        if not ts_str:
            return None
        try:
            # Handle ISO string with or without Z
            clean = ts_str.replace("Z", "+00:00")
            return datetime.fromisoformat(clean)
        except Exception:
            return None

    @classmethod
    def _get_authority_tier(cls, ev: Evidence) -> int:
        """
        Determines domain-agnostic source authority tier:
        Tier 3: Approved Specifications, Architecture Policies, Merged Master Commits
        Tier 2: Production Incident Reports, Post-Mortems, Change Requests, Resolved Tickets
        Tier 1: Draft PRs, Personal Branches, Unmerged Commits, Review Comments, Scratch
        """
        # 1. Check explicit metadata authority if present
        meta_auth = str(ev.metadata.get("authority_level", "")).upper()
        if meta_auth in ["SPECIFICATION", "POLICY", "APPROVED"]:
            return 3
        if meta_auth in ["OPERATIONAL", "INCIDENT", "PRODUCTION"]:
            return 2
        if meta_auth in ["DRAFT", "WORKING", "SCRATCH"]:
            return 1

        # 2. Derive from source URI, source_id, and source_path
        identifier = f"{ev.source_id} {ev.uri or ''} {ev.source_path or ''}".lower()

        # Tier 1 indicators: draft, pull request, branch, test, personal, comment
        if any(term in identifier for term in ["draft", "pull/", "/pull/", "branch/", "wip", "review", "scratch", "tmp"]):
            return 1

        # Tier 3 indicators: architecture, spec, policy, rfc, standard, release
        if any(term in identifier for term in ["arch", "spec", "policy", "rfc", "standard", "canonical", "release"]):
            return 3

        # Default: standard operational evidence (tickets, logs, documentation)
        return 2

    @classmethod
    def _extract_entity_states(cls, content: str) -> Dict[str, str]:
        """
        Extracts mapping of entity -> state polarity ('POSITIVE' or 'NEGATIVE').
        """
        results: Dict[str, str] = {}
        content_lower = content.lower()

        # Find entity mentions
        raw_matches = ENTITY_PATTERN.findall(content)
        entities = set()
        for m in raw_matches:
            ent = (m[0] or m[1]).strip()
            if ent:
                entities.add(ent)
        for ent in entities:
            ent_clean = ent.lower()
            # Look for state keywords in the sentence or window near the entity
            # Split content into sentences
            sentences = [s.strip() for s in re.split(r"[\.\n;]", content_lower) if s.strip()]
            for s in sentences:
                if ent_clean in s:
                    words = set(re.findall(r"\b[a-z_\-]+\b", s))
                    has_pos = bool(words & POSITIVE_STATES)
                    has_neg = bool(words & NEGATIVE_STATES)
                    if has_pos and not has_neg:
                        results[ent_clean] = "POSITIVE"
                        break
                    elif has_neg and not has_pos:
                        results[ent_clean] = "NEGATIVE"
                        break
        return results

    @classmethod
    def detect_temporal_relationships(cls, evidence_items: List[Evidence]) -> List[EvidenceEdge]:
        """
        Detects SUPERSEDES and CONTRADICTS edges across heterogeneous evidence items
        based on state polarity, ISO-8601 timestamps, and source authority tiers.
        """
        edges: List[EvidenceEdge] = []
        n = len(evidence_items)
        if n < 2:
            return edges

        # Pre-extract entity states, timestamps, and authority tiers
        extracted_states = [cls._extract_entity_states(ev.content) for ev in evidence_items]
        timestamps = [cls._parse_timestamp(ev.created_at) for ev in evidence_items]
        authorities = [cls._get_authority_tier(ev) for ev in evidence_items]

        for i in range(n):
            for j in range(i + 1, n):
                ev_a = evidence_items[i]
                ev_b = evidence_items[j]

                states_a = extracted_states[i]
                states_b = extracted_states[j]

                # Find shared entities
                shared_entities = set(states_a.keys()) & set(states_b.keys())
                for entity in shared_entities:
                    pol_a = states_a[entity]
                    pol_b = states_b[entity]

                    if pol_a != pol_b:
                        # Opposing operational states detected!
                        dt_a = timestamps[i]
                        dt_b = timestamps[j]
                        auth_a = authorities[i]
                        auth_b = authorities[j]

                        if dt_a and dt_b and dt_a != dt_b:
                            if dt_a > dt_b:
                                newer, older = ev_a, ev_b
                                newer_pol = pol_a
                                newer_auth, older_auth = auth_a, auth_b
                            else:
                                newer, older = ev_b, ev_a
                                newer_pol = pol_b
                                newer_auth, older_auth = auth_b, auth_a

                            # Authority Check:
                            # A newer document of strictly weaker authority cannot supersede an older authoritative baseline
                            if newer_auth < older_auth:
                                edges.append(
                                    EvidenceEdge(
                                        source_evidence_id=newer.evidence_id,
                                        target_evidence_id=older.evidence_id,
                                        relationship_type=RelationshipType.CONTRADICTS,
                                        basis=(
                                            f"Authority-recency conflict for '{entity}': Newer source {newer.source_id} (Tier {newer_auth}) "
                                            f"has lower authority than older source {older.source_id} (Tier {older_auth})"
                                        ),
                                        derived_by=EdgeDerivationType.DETERMINISTIC_REFERENCE,
                                        confidence=1.0,
                                    )
                                )
                            else:
                                edges.append(
                                    EvidenceEdge(
                                        source_evidence_id=newer.evidence_id,
                                        target_evidence_id=older.evidence_id,
                                        relationship_type=RelationshipType.SUPERSEDES,
                                        basis=(
                                            f"Temporal supersession: {newer.source_id} ({newer.created_at}) "
                                            f"supersedes {older.source_id} ({older.created_at}) for '{entity}' "
                                            f"({newer_pol.lower()} state supersedes previous state)"
                                        ),
                                        derived_by=EdgeDerivationType.DETERMINISTIC_REFERENCE,
                                        confidence=1.0,
                                    )
                                )
                        else:
                            # Timestamps are identical, missing, or inconclusive -> direct contradiction
                            edges.append(
                                EvidenceEdge(
                                    source_evidence_id=ev_a.evidence_id,
                                    target_evidence_id=ev_b.evidence_id,
                                    relationship_type=RelationshipType.CONTRADICTS,
                                    basis=(
                                        f"Unreconciled operational state conflict for '{entity}': "
                                        f"{ev_a.source_id} ({pol_a}) vs {ev_b.source_id} ({pol_b})"
                                    ),
                                    derived_by=EdgeDerivationType.DETERMINISTIC_REFERENCE,
                                    confidence=1.0,
                                )
                            )

        return edges
