"""
Security Intelligence API Facade (Brick 4.7)

Provides unified application-level operations for security intelligence:
- ingest_finding(...)
- get_finding(...)
- investigate_security(...)
- get_security_decision(...)
- get_remediation_candidates(...)
- get_contradictions(...)
- verify_remediation(...)

Guarantees:
- Enforces multi-tenant isolation and repository boundaries.
- Thread-safe registries.
"""

from __future__ import annotations

import threading
from typing import Any, Dict, List, Optional

from backend.release.security.decision import SecurityDecisionEngine
from backend.release.security.investigation import SecurityInvestigationEngine
from backend.release.security.models import (
    RemediationCandidate,
    SecurityContradictionRecord,
    SecurityDecision,
    SecurityFinding,
    SecurityInvestigation,
    SecurityVerification,
)
from backend.release.security.normalizer import SecurityFindingNormalizer
from backend.release.security.verification import SecurityVerificationEngine


class SecurityIntelligenceAPI:
    """
    Unified application facade for ORACLE Security Intelligence Engine.
    """

    def __init__(
        self,
        investigation_engine: Optional[SecurityInvestigationEngine] = None,
        normalizer: Optional[SecurityFindingNormalizer] = None,
        verification_engine: Optional[SecurityVerificationEngine] = None,
    ):
        self.investigation_engine = investigation_engine or SecurityInvestigationEngine()
        self.normalizer = normalizer or SecurityFindingNormalizer()
        self.verification_engine = verification_engine or SecurityVerificationEngine()

        # In-memory session registries: tenant_id -> key -> object
        self._findings: Dict[str, Dict[str, SecurityFinding]] = {}
        self._investigations: Dict[str, Dict[str, SecurityInvestigation]] = {}
        self._lock = threading.RLock()

    def ingest_finding(
        self,
        raw_finding: Dict[str, Any],
        repository: str,
        commit: str,
        tenant_id: str = "default",
        artifact_digest: Optional[str] = None,
        scanner_hint: Optional[str] = None,
    ) -> SecurityFinding:
        """Normalize, bind, and register an incoming security finding."""
        with self._lock:
            finding = self.normalizer.normalize(
                raw_finding=raw_finding,
                repository=repository,
                commit=commit,
                scanner_hint=scanner_hint,
                tenant_id=tenant_id,
                artifact_digest=artifact_digest,
            )
            # Create evidence reference
            self.normalizer.to_evidence(finding)

            tenant_dict = self._findings.setdefault(tenant_id, {})
            tenant_dict[finding.finding_id] = finding
            return finding

    def get_finding(self, finding_id: str, tenant_id: str = "default") -> Optional[SecurityFinding]:
        """Retrieve finding by ID within tenant boundary."""
        with self._lock:
            return self._findings.get(tenant_id, {}).get(finding_id)

    def investigate_security(
        self,
        repository: str,
        commit: str,
        tenant_id: str = "default",
        artifact_digest: Optional[str] = None,
        raw_findings: Optional[List[Dict[str, Any]]] = None,
        call_graph: Optional[Dict[str, List[str]]] = None,
        registered_routes: Optional[List[str]] = None,
        imported_symbols: Optional[Dict[str, Any]] = None,
        manifest_data: Optional[Dict[str, Any]] = None,
        lockfile_data: Optional[Dict[str, Any]] = None,
        dependency_graph: Optional[List[Any]] = None,
        dev_packages: Optional[Any] = None,
        compensating_controls: Optional[List[Any]] = None,
        verifications: Optional[List[SecurityVerification]] = None,
        is_evidence_stale: bool = False,
        build_artifact: Optional[Any] = None,
        deployment: Optional[Any] = None,
        runtime_service: Optional[Any] = None,
        business_context: Optional[Any] = None,
    ) -> SecurityInvestigation:
        """Run an end-to-end security investigation for a repository commit/artifact."""
        with self._lock:
            # Include already registered findings for this repo & commit & tenant
            existing_findings = [
                f for f in self._findings.get(tenant_id, {}).values()
                if f.repository.lower() == repository.lower() and f.commit.lower() == commit.lower()
            ]

            investigation = self.investigation_engine.investigate(
                repository=repository,
                commit=commit,
                tenant_id=tenant_id,
                artifact_digest=artifact_digest,
                raw_findings=raw_findings,
                normalized_findings=existing_findings,
                manifest_data=manifest_data,
                lockfile_data=lockfile_data,
                dependency_graph=dependency_graph,
                dev_packages=dev_packages,
                call_graph=call_graph,
                registered_routes=registered_routes,
                imported_symbols=imported_symbols,
                compensating_controls=compensating_controls,
                verifications=verifications,
                is_evidence_stale=is_evidence_stale,
                build_artifact=build_artifact,
                deployment=deployment,
                runtime_service=runtime_service,
                business_context=business_context,
            )

            tenant_invs = self._investigations.setdefault(tenant_id, {})
            tenant_invs[investigation.investigation_id] = investigation
            # Also key by repository:commit for fast lookup
            tenant_invs[f"{repository}:{commit}"] = investigation

            return investigation

    def get_investigation(
        self,
        investigation_id: str,
        tenant_id: str = "default",
    ) -> Optional[SecurityInvestigation]:
        """Retrieve security investigation by ID or target."""
        with self._lock:
            return self._investigations.get(tenant_id, {}).get(investigation_id)

    def get_impact(
        self,
        finding_id_or_assessment_id: str,
        tenant_id: str = "default",
    ) -> Optional[Any]:
        """Retrieve security impact assessment by finding or assessment ID."""
        with self._lock:
            tenant_invs = self._investigations.get(tenant_id, {})
            for inv in tenant_invs.values():
                if inv.impact_assessments:
                    for imp in inv.impact_assessments:
                        if imp.finding_id == finding_id_or_assessment_id or imp.assessment_id == finding_id_or_assessment_id:
                            return imp
            return None

    def get_lineage(
        self,
        target_id: str,
        tenant_id: str = "default",
    ) -> Dict[str, Any]:
        """Retrieve decision and evidence lineage for finding or investigation."""
        with self._lock:
            finding = self.get_finding(target_id, tenant_id=tenant_id)
            inv = self.get_investigation(target_id, tenant_id=tenant_id)
            
            # If target_id is a finding, look for parent investigation
            if finding and not inv:
                tenant_invs = self._investigations.get(tenant_id, {})
                for candidate in tenant_invs.values():
                    if any(f.finding_id == target_id for f in candidate.findings):
                        inv = candidate
                        break

            return {
                "target_id": target_id,
                "tenant_id": tenant_id,
                "finding": finding.model_dump() if finding else None,
                "investigation_id": inv.investigation_id if inv else None,
                "decision": inv.decision.model_dump() if inv and inv.decision else None,
                "contradictions": [c.model_dump() for c in inv.contradictions] if inv else [],
                "provenance": inv.decision.provenance if inv and inv.decision else {},
            }

    def get_security_decision(
        self,
        investigation_id_or_target: str,
        tenant_id: str = "default",
    ) -> Optional[SecurityDecision]:
        """Retrieve authoritative SecurityDecision by investigation ID or target."""
        with self._lock:
            inv = self._investigations.get(tenant_id, {}).get(investigation_id_or_target)
            return inv.decision if inv else None

    def get_remediation_candidates(
        self,
        investigation_id_or_target: str,
        tenant_id: str = "default",
    ) -> List[RemediationCandidate]:
        """Retrieve remediation candidates from the latest investigation."""
        with self._lock:
            inv = self._investigations.get(tenant_id, {}).get(investigation_id_or_target)
            if inv and inv.decision:
                return inv.decision.recommendations
            return []

    def get_contradictions(
        self,
        investigation_id_or_target: str,
        tenant_id: str = "default",
    ) -> List[SecurityContradictionRecord]:
        """Retrieve contradictions detected during investigation."""
        with self._lock:
            inv = self._investigations.get(tenant_id, {}).get(investigation_id_or_target)
            return inv.contradictions if inv else []

    def verify_remediation(
        self,
        finding_id: str,
        fixed_commit: str,
        rescan_findings: Optional[List[SecurityFinding]] = None,
        rescan_artifact_digest: Optional[str] = None,
        pr_merged: bool = True,
        tenant_id: str = "default",
    ) -> SecurityVerification:
        """Execute closed-loop remediation verification against rescan evidence."""
        with self._lock:
            finding = self.get_finding(finding_id, tenant_id=tenant_id)
            if not finding:
                raise ValueError(f"Security finding '{finding_id}' not found in tenant '{tenant_id}'.")

            verification = self.verification_engine.verify_remediation(
                original_finding=finding,
                fixed_commit=fixed_commit,
                rescan_findings=rescan_findings,
                rescan_artifact_digest=rescan_artifact_digest,
                pr_merged=pr_merged,
                tenant_id=tenant_id,
            )

            # If verified resolved, update finding status
            if verification.status.value == "VERIFIED_RESOLVED":
                finding.status = finding.status.RESOLVED

            return verification
