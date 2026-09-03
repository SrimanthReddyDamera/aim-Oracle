"""
ORACLE Epistemic Evidence Synthesizer (Brick 4.0)
Consumes a verified EvidencePackage from InvestigationController and produces
an authoritative SynthesisResult with verified claims, causal graphs, and exact citations.
Strictly domain-agnostic and enforces epistemic verification rules.
"""

import re
import time
from typing import Any, Callable, Dict, List, Optional, Set

from backend.core.security import redact_sensitive_text
from backend.evidence.models import Evidence
from backend.investigation.models import (
    EvidenceEdge,
    EvidencePackage,
    GapStatus,
    InformationGap,
    RelationshipType,
)
from backend.synthesis.citations import CitationResolver
from backend.synthesis.entailment import EntailmentVerifier
from backend.synthesis.models import (
    Claim,
    ClaimType,
    Citation,
    InsufficientEvidenceReport,
    ReconciliationReport,
    SynthesisResult,
    SynthesisStatus,
    VerificationState,
)


def _sanitize_heading_text(text: str, max_length: int = 80) -> str:
    """
    Sanitize text for embedding inside markdown headings:
    - Escapes Markdown structural characters (#, *, _, `, [, ], (, ), <, >, |, \\)
    - Replaces newlines/carriage returns/tabs with spaces
    - Imposes a strict length ceiling (default 80 characters)
    """
    if not text:
        return "Untitled Objective"
    clean = " ".join(text.split())
    clean = re.sub(r"([#*`_\[\]()<>\\|])", r"\\\1", clean)
    if len(clean) > max_length:
        clean = clean[:max_length].rstrip() + "..."
    return clean


class EvidenceSynthesizer:
    """
    Epistemic Synthesis Engine.
    Enforces controller-owned verification gates, exact provenance citation mapping,
    and structured insufficiency and reconciliation fallbacks.
    """

    def __init__(
        self,
        model_gateway: Optional[Any] = None,
        prompt_template: Optional[str] = None,
    ):
        self.model_gateway = model_gateway
        self.prompt_template = prompt_template

    def synthesize(
        self,
        package: EvidencePackage,
        agent_claim_extractor_fn: Optional[Callable[[str, List[Evidence]], List[Claim]]] = None,
    ) -> SynthesisResult:
        """
        Synthesizes an EvidencePackage into an authoritative SynthesisResult.
        Guarantees:
          - If controller_verified is False or blocking gaps remain -> INSUFFICIENT_EVIDENCE
          - If contradictions remain -> RECONCILIATION_REQUIRED
          - If verified -> SUCCESS with verified claims and exact citations
        """
        t0 = time.perf_counter()
        evidence_map: Dict[str, Evidence] = {e.evidence_id: e for e in package.evidence_items}

        # ---------------------------------------------------------------------
        # GATE 1: VERIFICATION GATE
        # ---------------------------------------------------------------------
        blocking_open_gaps = [
            g for g in package.gaps
            if g.is_blocking and g.status in [
                GapStatus.OPEN,
                GapStatus.INVESTIGATING,
                GapStatus.UNRESOLVED,
                GapStatus.BLOCKED,
            ]
        ]

        if not package.controller_verified or blocking_open_gaps or not package.evidence_items:
            elapsed_ms = (time.perf_counter() - t0) * 1000.0
            return self._build_insufficient_result(
                package=package,
                blocking_gaps=blocking_open_gaps,
                evidence_map=evidence_map,
                elapsed_ms=elapsed_ms,
            )

        # ---------------------------------------------------------------------
        # GATE 2: CONTRADICTION / RECONCILIATION GATE
        # ---------------------------------------------------------------------
        contradict_edges = [
            e for e in package.graph_edges
            if e.relationship_type == RelationshipType.CONTRADICTS
        ]
        reconcile_gaps = [
            g for g in package.gaps
            if g.status == GapStatus.RECONCILIATION_REQUIRED
        ]

        if contradict_edges or reconcile_gaps:
            elapsed_ms = (time.perf_counter() - t0) * 1000.0
            return self._build_reconciliation_result(
                package=package,
                contradict_edges=contradict_edges,
                reconcile_gaps=reconcile_gaps,
                evidence_map=evidence_map,
                elapsed_ms=elapsed_ms,
            )

        # Identify superseded evidence items
        superseded_ev_ids = {
            e.target_evidence_id for e in package.graph_edges
            if e.relationship_type == RelationshipType.SUPERSEDES
        }

        # ---------------------------------------------------------------------
        # GATE 3: CLAIM EXTRACTION & EVIDENCE GROUNDING
        # ---------------------------------------------------------------------
        if agent_claim_extractor_fn:
            raw_claims = agent_claim_extractor_fn(package.objective, package.evidence_items)
        else:
            raw_claims = self._default_claim_extractor(package.objective, package.evidence_items)

        # Filter and validate claims: every claim must have >= 1 valid admitted evidence_id
        # and be strictly entailed by the cited evidence
        verified_claims: List[Claim] = []
        for idx, claim in enumerate(raw_claims):
            # Check evidence backing
            valid_ev_ids = [eid for eid in claim.evidence_ids if eid in evidence_map]
            if not valid_ev_ids:
                # Claim is unbacked by admitted evidence -> strictly rejected
                continue

            # If all cited evidence items are superseded and newer non-superseded items exist, skip stale claim
            if all(eid in superseded_ev_ids for eid in valid_ev_ids) and any(eid not in superseded_ev_ids for eid in evidence_map):
                continue

            # Verify semantic entailment against cited evidence
            entailed_ev_ids = []
            for eid in valid_ev_ids:
                ev = evidence_map[eid]
                is_entailed, _ = EntailmentVerifier.verify_claim_entailment(claim, ev)
                if is_entailed:
                    entailed_ev_ids.append(eid)

            if not entailed_ev_ids:
                # Claim statement contradicts, inverts, or fabricates facts beyond cited evidence
                continue

            verified_claim = Claim(
                claim_id=claim.claim_id or f"claim_{idx+1}",
                statement=redact_sensitive_text(claim.statement.strip()),
                evidence_ids=entailed_ev_ids,
                verbatim_anchor=redact_sensitive_text(claim.verbatim_anchor) if claim.verbatim_anchor else None,
                claim_type=claim.claim_type,
                verification_state=VerificationState.VERIFIED,
                confidence=claim.confidence,
                causal_predecessors=list(claim.causal_predecessors),
            )
            verified_claims.append(verified_claim)

        if not verified_claims:
            elapsed_ms = (time.perf_counter() - t0) * 1000.0
            return self._build_insufficient_result(
                package=package,
                blocking_gaps=[],
                evidence_map=evidence_map,
                elapsed_ms=elapsed_ms,
            )

        # ---------------------------------------------------------------------
        # GATE 4: CAUSAL GRAPH LINKING
        # ---------------------------------------------------------------------
        self._link_causal_relationships(verified_claims, package.graph_edges)

        # ---------------------------------------------------------------------
        # GATE 5: DETERMINISTIC CITATION RESOLUTION & ANSWER COMPOSITION
        # ---------------------------------------------------------------------
        all_cited_ev_ids = []
        for c in verified_claims:
            all_cited_ev_ids.extend(c.evidence_ids)

        citations, ev_to_marker = CitationResolver.resolve_citations_for_evidence_ids(
            all_cited_ev_ids, evidence_map
        )

        safe_heading = _sanitize_heading_text(package.objective)
        answer_paragraphs = [f"## Investigation Finding: {safe_heading}\n"]
        for c in verified_claims:
            markers = " ".join([ev_to_marker[eid] for eid in c.evidence_ids if eid in ev_to_marker])
            if c.causal_predecessors:
                causal_note = f" *(Prequisite: {', '.join(c.causal_predecessors)})*"
            else:
                causal_note = ""
            clean_stmt = " ".join(c.statement.split())
            clean_stmt = re.sub(r"^(?:#+\s*)", "", clean_stmt)
            answer_paragraphs.append(f"- {clean_stmt} {markers}{causal_note}")

        footnotes = CitationResolver.render_footnote_block(citations)
        raw_answer = "\n".join(answer_paragraphs) + footnotes
        safe_answer = redact_sensitive_text(raw_answer)

        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        return SynthesisResult(
            status=SynthesisStatus.SUCCESS,
            objective=package.objective,
            final_answer=safe_answer,
            claims=verified_claims,
            citations=citations,
            evidence_count=len(package.evidence_items),
            synthesis_wall_time_ms=round(elapsed_ms, 2),
        )

    # -------------------------------------------------------------------------
    # INTERNAL HELPERS & FALLBACK GENERATORS
    # -------------------------------------------------------------------------
    def _default_claim_extractor(self, objective: str, evidence_items: List[Evidence]) -> List[Claim]:
        """
        Deterministic default claim extractor when no custom LLM extractor is injected.
        Synthesizes direct assertions grounded in admitted evidence chunks.
        """
        claims: List[Claim] = []
        for idx, ev in enumerate(evidence_items):
            first_line = ev.content.strip().split("\n")[0].strip("#* ").strip()
            if not first_line:
                first_line = f"Evidence from {ev.source_id}"

            statement = f"Verified from {ev.source_id}: {first_line}"
            claims.append(
                Claim(
                    claim_id=f"claim_{idx+1}",
                    statement=statement,
                    evidence_ids=[ev.evidence_id],
                    verbatim_anchor=redact_sensitive_text(first_line),
                    claim_type=ClaimType.FACTUAL_ASSERTION,
                    confidence=1.0,
                )
            )
        return claims

    def _link_causal_relationships(self, claims: List[Claim], edges: List[EvidenceEdge]) -> None:
        """
        Maps DEPENDS_ON evidence edges to causal_predecessors across claims.
        """
        ev_to_claims: Dict[str, List[Claim]] = {}
        for c in claims:
            for eid in c.evidence_ids:
                ev_to_claims.setdefault(eid, []).append(c)

        for edge in edges:
            if edge.relationship_type == RelationshipType.DEPENDS_ON:
                source_claims = ev_to_claims.get(edge.source_evidence_id, [])
                target_claims = ev_to_claims.get(edge.target_evidence_id, [])
                for sc in source_claims:
                    for tc in target_claims:
                        if tc.claim_id not in sc.causal_predecessors and tc.claim_id != sc.claim_id:
                            sc.causal_predecessors.append(tc.claim_id)

    def _build_insufficient_result(
        self,
        package: EvidencePackage,
        blocking_gaps: List[InformationGap],
        evidence_map: Dict[str, Evidence],
        elapsed_ms: float,
    ) -> SynthesisResult:
        """Constructs an authoritative Insufficient Evidence response."""
        what_is_known = []
        for ev in package.evidence_items[:5]:
            snippet = " ".join(ev.content.split())[:100]
            what_is_known.append(redact_sensitive_text(f"[{ev.source_type.upper()}] {ev.source_id}: \"{snippet}...\""))

        missing_reqs = []
        open_gap_dicts = []
        suggested_queries = []
        for g in blocking_gaps:
            req = g.required_information or g.description
            missing_reqs.append(f"{g.target_entity or 'Target'}: {req}")
            open_gap_dicts.append({
                "gap_id": g.gap_id,
                "gap_type": g.gap_type.value,
                "target_entity": g.target_entity,
                "description": g.description,
                "status": g.status.value,
            })
            suggested_queries.extend(g.attempted_queries or [g.targeted_query])

        if not missing_reqs and not package.controller_verified:
            missing_reqs.append("The investigation terminated before proving factual sufficiency.")

        report = InsufficientEvidenceReport(
            objective=package.objective,
            what_is_known=what_is_known,
            missing_requirements=missing_reqs,
            open_gaps=open_gap_dicts,
            suggested_investigation_queries=list(set(suggested_queries)),
        )

        safe_heading = _sanitize_heading_text(package.objective)
        explanation_lines = [
            f"## Insufficient Evidence: {safe_heading}",
            "\nA definitive factual conclusion cannot be rendered because the investigation state is unverified or incomplete.",
            f"- **Termination State:** `{package.termination_reason}`",
            f"- **Controller Verified:** `{package.controller_verified}`",
            f"- **Open Blocking Gaps:** {len(blocking_gaps)}",
            "\n### What is Known:",
        ]
        for item in (what_is_known or ["No verifiable evidence was admitted."]):
            explanation_lines.append(f"- {item}")

        explanation_lines.append("\n### Missing Requirements:")
        for req in (missing_reqs or ["Corroborating proof required."]):
            explanation_lines.append(f"- {req}")

        safe_answer = redact_sensitive_text("\n".join(explanation_lines))
        return SynthesisResult(
            status=SynthesisStatus.INSUFFICIENT_EVIDENCE,
            objective=package.objective,
            final_answer=safe_answer,
            claims=[],
            citations=[],
            insufficient_report=report,
            evidence_count=len(package.evidence_items),
            synthesis_wall_time_ms=round(elapsed_ms, 2),
        )

    def _build_reconciliation_result(
        self,
        package: EvidencePackage,
        contradict_edges: List[EvidenceEdge],
        reconcile_gaps: List[InformationGap],
        evidence_map: Dict[str, Evidence],
        elapsed_ms: float,
    ) -> SynthesisResult:
        """Constructs an explicit Reconciliation Required response."""
        contradictions = []
        opposing_claims = []

        for edge in contradict_edges:
            ev_src = evidence_map.get(edge.source_evidence_id)
            ev_tgt = evidence_map.get(edge.target_evidence_id)
            src_desc = f"{ev_src.source_id} ({ev_src.evidence_id})" if ev_src else edge.source_evidence_id
            tgt_desc = f"{ev_tgt.source_id} ({ev_tgt.evidence_id})" if ev_tgt else edge.target_evidence_id
            
            contradictions.append({
                "source_evidence_id": edge.source_evidence_id,
                "target_evidence_id": edge.target_evidence_id,
                "basis": edge.basis,
            })
            opposing_claims.append({
                "claim_a": src_desc,
                "claim_b": tgt_desc,
                "basis": edge.basis,
            })

        for gap in reconcile_gaps:
            contradictions.append({
                "gap_id": gap.gap_id,
                "description": gap.description,
                "conflicting_evidence_ids": gap.conflicting_evidence_ids,
            })

        report = ReconciliationReport(
            objective=package.objective,
            contradictions=contradictions,
            opposing_claims=opposing_claims,
            arbitration_basis="Contradictory evidence detected across admitted sources. Manual arbitration or temporal ordering required.",
        )

        safe_heading = _sanitize_heading_text(package.objective)
        explanation_lines = [
            f"## Reconciliation Required: {safe_heading}",
            "\nThe investigation discovered mutually conflicting claims that cannot be silently collapsed into a single fact.",
            "\n### Detected Contradictions:",
        ]
        for c in opposing_claims:
            explanation_lines.append(f"- **Conflict:** {c['claim_a']} *vs* {c['claim_b']} (Basis: {c['basis']})")

        safe_answer = redact_sensitive_text("\n".join(explanation_lines))
        return SynthesisResult(
            status=SynthesisStatus.RECONCILIATION_REQUIRED,
            objective=package.objective,
            final_answer=safe_answer,
            claims=[],
            citations=[],
            reconciliation_report=report,
            evidence_count=len(package.evidence_items),
            synthesis_wall_time_ms=round(elapsed_ms, 2),
        )
