"""
Business & Operational Impact Engine (Brick 4.8)

Correlates security findings with operational business entities:
1. Distinguishes: Security Severity != Security Impact != Business Impact.
2. Evaluates evidence-backed business tier (Tier 0/1, Mission Critical, Production).
3. Detects critical business paths (payments, billing, identity, authentication) when explicitly proven by evidence.
4. Factored against active production incidents and deployment environments.
5. Strict invariant: Never infers business criticality from service names alone.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Set
from pydantic import BaseModel, Field

from backend.evidence.models import Evidence
from backend.release.models import ReleaseCandidate, WorkItem
from backend.release.security.models import (
    BusinessImpactLevel,
    DeploymentEnvironment,
    RuntimeService,
)


class BusinessImpactAssessment(BaseModel):
    """Deliverable of business and operational impact evaluation."""
    target_service_id: str
    impact_level: BusinessImpactLevel = BusinessImpactLevel.UNKNOWN
    is_production: bool = False
    is_critical_path: bool = False
    active_incidents_count: int = 0
    linked_blockers: List[str] = Field(default_factory=list)
    evidence_references: List[str] = Field(default_factory=list)
    rationale: str = ""
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)


class BusinessImpactEngine:
    """
    Deterministic business and operational impact evaluator.
    Strictly forbids guessing from service names; requires explicit metadata or evidence.
    """

    CRITICAL_PATH_TYPES = {
        "payment", "checkout", "billing", "identity", "authentication",
        "auth", "pci_dss", "sox", "hipaa", "financial_transaction"
    }

    def evaluate_business_impact(
        self,
        service: Optional[RuntimeService] = None,
        candidate: Optional[ReleaseCandidate] = None,
        environment: Optional[DeploymentEnvironment] = None,
        operational_evidence: Optional[List[Evidence]] = None,
        work_items: Optional[List[WorkItem]] = None,
        active_incidents: Optional[List[Any]] = None,
        route_or_entrypoint: Optional[str] = None,
    ) -> BusinessImpactAssessment:
        """
        Evaluate business impact based purely on explicit evidence and operational context.
        """
        service_id = service.service_id if service else (candidate.service_name if candidate else "unknown")
        evidence_list = operational_evidence or []
        evidence_refs: List[str] = []

        # 1. Determine Environment
        target_env = environment
        if not target_env and service:
            target_env = service.environment
        if not target_env and candidate:
            env_str = candidate.target_environment.upper()
            if env_str in DeploymentEnvironment.__members__:
                target_env = DeploymentEnvironment[env_str]
            else:
                target_env = DeploymentEnvironment.PRODUCTION if "prod" in env_str.lower() else DeploymentEnvironment.DEVELOPMENT

        is_prod = target_env == DeploymentEnvironment.PRODUCTION if target_env else False

        # 2. Inspect Tier & Criticality from explicit Service metadata
        service_tier: Optional[str] = None
        if service and service.criticality_tier:
            service_tier = service.criticality_tier.upper()

        # 3. Inspect Operational Evidence items
        is_critical_path = False
        critical_reasons: List[str] = []

        for ev in evidence_list:
            ev_meta = ev.metadata or {}
            evidence_refs.append(ev.evidence_id)

            if "criticality_tier" in ev_meta:
                service_tier = str(ev_meta["criticality_tier"]).upper()
            if ev_meta.get("is_production") is not None:
                is_prod = bool(ev_meta["is_production"])

            # Check explicit business path tagging in metadata
            bus_path = ev_meta.get("business_path_type") or ev_meta.get("compliance_scope")
            if bus_path and str(bus_path).lower() in self.CRITICAL_PATH_TYPES:
                is_critical_path = True
                critical_reasons.append(f"Explicit {bus_path} path verified by {ev.source_type}")

        # Check route or entrypoint tag if explicitly passed
        if route_or_entrypoint:
            route_lower = route_or_entrypoint.lower()
            # If metadata explicitly flags route as financial/auth
            for tag in self.CRITICAL_PATH_TYPES:
                if f"/{tag}" in route_lower or f"_{tag}" in route_lower:
                    is_critical_path = True
                    critical_reasons.append(f"Target route matches critical business domain: {tag}")
                    break

        # 4. Check active incidents
        active_inc_count = len(active_incidents) if active_incidents else 0
        linked_blockers = []
        if work_items:
            for wi in work_items:
                if wi.is_blocking or wi.is_incident:
                    linked_blockers.append(wi.item_id)

        # 5. Deterministic Impact Level Computation
        rationale_parts: List[str] = []

        if not target_env and not service_tier and not evidence_list:
            impact_level = BusinessImpactLevel.UNKNOWN
            rationale_parts.append("No operational tier, environment, or business path evidence provided. Business impact UNKNOWN.")
            conf = 0.5
        elif is_prod and (service_tier in ("TIER_0", "TIER_1", "CRITICAL") or is_critical_path or active_inc_count > 0):
            impact_level = BusinessImpactLevel.CRITICAL
            rationale_parts.append("Critical production operation: ")
            if service_tier in ("TIER_0", "TIER_1", "CRITICAL"):
                rationale_parts.append(f"Service rated {service_tier}; ")
            if is_critical_path:
                rationale_parts.append(f"Executes core business transaction path ({'; '.join(critical_reasons)}); ")
            if active_inc_count > 0:
                rationale_parts.append(f"Service has {active_inc_count} active incidents; ")
            conf = 1.0
        elif is_prod:
            impact_level = BusinessImpactLevel.HIGH
            rationale_parts.append("Production environment deployment with standard operational tier.")
            conf = 0.9
        elif target_env in (DeploymentEnvironment.STAGING, DeploymentEnvironment.CANARY):
            impact_level = BusinessImpactLevel.MODERATE
            rationale_parts.append(f"Pre-production deployment environment ({target_env.value}).")
            conf = 0.95
        else:
            impact_level = BusinessImpactLevel.LOW
            rationale_parts.append(f"Non-production / development environment ({target_env.value if target_env else 'dev'}).")
            conf = 1.0

        return BusinessImpactAssessment(
            target_service_id=service_id,
            impact_level=impact_level,
            is_production=is_prod,
            is_critical_path=is_critical_path,
            active_incidents_count=active_inc_count,
            linked_blockers=linked_blockers,
            evidence_references=evidence_refs,
            rationale="".join(rationale_parts),
            confidence=conf,
        )
