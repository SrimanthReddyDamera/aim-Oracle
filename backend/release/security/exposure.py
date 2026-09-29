"""
Runtime Exposure Intelligence Engine (Brick 4.8)

Provides deterministic, evidence-grounded runtime exposure evaluation:
1. Evaluates explicit network configuration, ingress routes, and security groups.
2. Distinguishes INTERNET_FACING, INTERNAL, PRIVATE_NETWORK, and UNKNOWN.
3. Evaluates authentication posture: AUTHENTICATED, UNAUTHENTICATED, or UNKNOWN.
4. INVARIANT: Never infers exposure from service names or arbitrary lexical tokens.
   If explicit evidence is missing, UNKNOWN is strictly preserved.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Set, Tuple
from pydantic import BaseModel, Field

from backend.evidence.models import Evidence
from backend.release.security.models import (
    AuthRequirement,
    CompensatingControl,
    DeploymentEnvironment,
    NetworkExposure,
    RuntimeService,
)


class RuntimeExposureAssessment(BaseModel):
    """Authoritative assessment of runtime service network exposure and auth posture."""
    service_id: str
    exposure: NetworkExposure = NetworkExposure.UNKNOWN
    auth_requirement: AuthRequirement = AuthRequirement.UNKNOWN
    matched_entry_points: List[str] = Field(default_factory=list)
    active_controls: List[CompensatingControl] = Field(default_factory=list)
    evidence_references: List[str] = Field(default_factory=list)
    has_conflicting_evidence: bool = False
    conflicting_sources: List[str] = Field(default_factory=list)
    rationale: str = ""
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)


class RuntimeExposureEngine:
    """
    Deterministic runtime exposure evaluator.
    Strictly forbids naming-based heuristics; requires explicit configuration or network evidence.
    """

    def evaluate_exposure(
        self,
        service: Optional[RuntimeService] = None,
        network_evidence: Optional[List[Evidence]] = None,
        target_route: Optional[str] = None,
        entry_point: Optional[str] = None,
    ) -> RuntimeExposureAssessment:
        """
        Evaluate runtime exposure backed by explicit evidence.
        """
        service_id = service.service_id if service else "unknown-service"
        evidence_list = network_evidence or []
        evidence_refs: List[str] = []

        # Collect claims from explicit evidence items
        exposure_claims: List[Tuple[str, NetworkExposure]] = []
        auth_claims: List[Tuple[str, AuthRequirement]] = []
        matched_routes: List[str] = []
        active_controls: List[CompensatingControl] = []

        # 1. Inspect Service entity if provided
        if service:
            if service.exposure != NetworkExposure.UNKNOWN:
                exposure_claims.append(("service_entity", service.exposure))
            if service.auth_required != AuthRequirement.UNKNOWN:
                auth_claims.append(("service_entity", service.auth_required))
            if service.active_compensating_controls:
                active_controls.extend(service.active_compensating_controls)
            if service.entry_points:
                matched_routes.extend(service.entry_points)

        # 2. Inspect explicit evidence items (e.g. k8s ingress, envoy route, aws sg, terraform)
        for ev in evidence_list:
            ev_meta = ev.metadata or {}
            source = ev.source_type or "network_evidence"
            evidence_refs.append(ev.evidence_id)

            # Check network exposure evidence
            if "network_exposure" in ev_meta:
                exp_str = str(ev_meta["network_exposure"]).upper()
                if exp_str in NetworkExposure.__members__:
                    exposure_claims.append((source, NetworkExposure[exp_str]))
            elif ev_meta.get("is_internet_facing") is True or ev_meta.get("public_ingress") is True:
                exposure_claims.append((source, NetworkExposure.INTERNET_FACING))
            elif ev_meta.get("is_internal_only") is True or ev_meta.get("private_cluster") is True:
                exposure_claims.append((source, NetworkExposure.INTERNAL))
            elif ev_meta.get("is_air_gapped") is True:
                exposure_claims.append((source, NetworkExposure.PRIVATE_NETWORK))

            # Check authentication requirement evidence
            if "auth_requirement" in ev_meta:
                auth_str = str(ev_meta["auth_requirement"]).upper()
                if auth_str in AuthRequirement.__members__:
                    auth_claims.append((source, AuthRequirement[auth_str]))
            elif ev_meta.get("auth_required") is True or ev_meta.get("requires_jwt") is True or ev_meta.get("requires_auth") is True:
                auth_claims.append((source, AuthRequirement.AUTHENTICATED))
            elif ev_meta.get("auth_required") is False or ev_meta.get("public_route") is True or ev_meta.get("anonymous_access") is True:
                auth_claims.append((source, AuthRequirement.UNAUTHENTICATED))

            # Check route bindings
            if "route" in ev_meta:
                matched_routes.append(ev_meta["route"])
            if "routes" in ev_meta and isinstance(ev_meta["routes"], list):
                matched_routes.extend(ev_meta["routes"])

            # Check controls in evidence
            if "compensating_control" in ev_meta:
                cc = ev_meta["compensating_control"]
                if isinstance(cc, dict):
                    try:
                        active_controls.append(CompensatingControl(**cc))
                    except Exception:
                        pass

        # 3. Detect conflicting exposure evidence
        has_exposure_conflict = False
        conflicting_sources: List[str] = []

        distinct_exposures = {exp for src, exp in exposure_claims if exp != NetworkExposure.UNKNOWN}
        if len(distinct_exposures) > 1:
            has_exposure_conflict = True
            conflicting_sources = [f"{src}:{exp.value}" for src, exp in exposure_claims]

        # 4. Determine final exposure
        if has_exposure_conflict:
            final_exposure = NetworkExposure.UNKNOWN
            rationale = f"Conflicting network exposure evidence detected: {', '.join(conflicting_sources)}."
        elif distinct_exposures:
            final_exposure = list(distinct_exposures)[0]
            rationale = f"Deterministic exposure established as {final_exposure.value} via explicit evidence."
        else:
            final_exposure = NetworkExposure.UNKNOWN
            rationale = "No explicit network configuration or ingress evidence provided. Exposure remains UNKNOWN (naming heuristics rejected)."

        # 5. Determine auth requirement
        distinct_auth = {a for src, a in auth_claims if a != AuthRequirement.UNKNOWN}
        if len(distinct_auth) > 1:
            final_auth = AuthRequirement.UNKNOWN
            rationale += f" Conflicting auth requirements detected across providers."
        elif distinct_auth:
            final_auth = list(distinct_auth)[0]
        else:
            final_auth = AuthRequirement.UNKNOWN

        # Match target route if given
        if target_route and target_route not in matched_routes:
            matched_routes.append(target_route)
        if entry_point and entry_point not in matched_routes:
            matched_routes.append(entry_point)

        return RuntimeExposureAssessment(
            service_id=service_id,
            exposure=final_exposure,
            auth_requirement=final_auth,
            matched_entry_points=list(set(matched_routes)),
            active_controls=active_controls,
            evidence_references=evidence_refs,
            has_conflicting_evidence=has_exposure_conflict,
            conflicting_sources=conflicting_sources,
            rationale=rationale,
            confidence=0.5 if has_exposure_conflict or final_exposure == NetworkExposure.UNKNOWN else 1.0,
        )
