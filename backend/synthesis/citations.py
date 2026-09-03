"""
ORACLE Epistemic Citation Engine (Brick 4.0)
Provides deterministic, tamper-evident citation generation from verified Evidence objects.
Strictly domain-agnostic: never hardcodes provider names or schemas.
"""

from typing import Dict, List, Optional, Tuple
from backend.core.security import redact_sensitive_text
from backend.evidence.models import Evidence
from backend.synthesis.models import Citation


class CitationResolver:
    """
    Pure, deterministic citation resolver.
    Transforms verified Evidence items into standardized Citation objects
    preserving exact source locations, URIs, byte offsets, and SHA-256 hashes.
    """

    @staticmethod
    def resolve_citation(evidence: Evidence, citation_index: int) -> Citation:
        """
        Derive a Citation object directly from an admitted Evidence object.
        Zero LLM involvement; zero fabricated URLs or offsets.
        Ensures all excerpts, URIs, and display references are scrubbed of secrets.
        """
        cit_marker = f"[{citation_index}]"

        # Determine display reference in a completely generic, domain-agnostic manner
        if evidence.uri and (evidence.uri.startswith("http://") or evidence.uri.startswith("https://")):
            display_ref = f"{evidence.source_type.upper()}: {evidence.source_id} ({evidence.uri})"
        elif evidence.source_path:
            display_ref = f"{evidence.source_path} (bytes {evidence.start_offset}-{evidence.end_offset})"
        else:
            display_ref = f"{evidence.source_type.upper()}: {evidence.source_id} (offset {evidence.start_offset}-{evidence.end_offset})"

        preview_len = 120
        clean_content = " ".join(evidence.content.split())
        preview = clean_content[:preview_len] + ("..." if len(clean_content) > preview_len else "")

        safe_display_ref = redact_sensitive_text(display_ref)
        safe_source_uri = redact_sensitive_text(evidence.uri or evidence.source_path) if (evidence.uri or evidence.source_path) else None
        safe_preview = redact_sensitive_text(preview)

        return Citation(
            citation_id=cit_marker,
            evidence_id=evidence.evidence_id,
            source_type=evidence.source_type,
            source_uri=safe_source_uri,
            display_reference=safe_display_ref,
            start_offset=evidence.start_offset,
            end_offset=evidence.end_offset,
            content_hash=evidence.content_hash,
            content_preview=safe_preview,
        )

    @classmethod
    def resolve_citations_for_evidence_ids(
        cls,
        evidence_ids: List[str],
        evidence_index: Dict[str, Evidence],
    ) -> Tuple[List[Citation], Dict[str, str]]:
        """
        Given a list of cited evidence IDs, returns:
          1. Ordered list of Citation objects.
          2. Mapping of evidence_id -> citation marker (e.g. "DOC-1" -> "[1]").
        """
        citations: List[Citation] = []
        ev_id_to_marker: Dict[str, str] = {}

        # Preserve deterministic order by sorting unique evidence_ids
        unique_sorted_ids = sorted(list(set(evidence_ids)))
        
        for idx, ev_id in enumerate(unique_sorted_ids, start=1):
            ev = evidence_index.get(ev_id)
            if not ev:
                continue
            cit = cls.resolve_citation(ev, citation_index=idx)
            citations.append(cit)
            ev_id_to_marker[ev_id] = cit.citation_id

        return citations, ev_id_to_marker

    @staticmethod
    def render_footnote_block(citations: List[Citation]) -> str:
        """
        Renders a standard markdown footnote block listing exact provenance details.
        """
        if not citations:
            return ""

        lines = ["\n\n### Evidence Provenance & Citations:"]
        for cit in citations:
            lines.append(
                f"- **{cit.citation_id}** `{cit.display_reference}` — "
                f"Offsets: `[{cit.start_offset}:{cit.end_offset}]` | "
                f"SHA-256: `{cit.content_hash[:12]}...`"
            )
            if cit.content_preview:
                lines.append(f"  *Excerpt:* \"{cit.content_preview}\"")

        return "\n".join(lines)
