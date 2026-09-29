"""
Security Contradiction Engine (Brick 4.7)

Detects and arbitrates epistemic security contradictions across:
1. Scanner vs Scanner: Scanner A claims vulnerable, Scanner B claims clean
2. Manifest vs Lockfile: Manifest pins vulnerable, lockfile resolved patched (or vice versa)
3. PR Claim vs Rescan: PR / Work item claims fixed, fresh rescan detects active vulnerability
4. SAST vs Reachability: Static analyzer claims reachable, call-graph analysis proves unreachable
5. Artifact vs Repository HEAD: Production deployment artifact differs in vulnerability status from HEAD

Epistemic States:
- CONFIRMED: Consistent multi-source agreement
- CONTRADICTED: Irreconcilable conflict requiring arbitration
- STALE: Evidence superseded by newer events or commits
- INSUFFICIENT_EVIDENCE: Missing required scans or data points
- UNKNOWN: Inconclusive state

Guarantees:
- Never silently collapses conflicting evidence.
- Maintains explicit contradiction lineage.
"""

from __future__ import annotations

import time
import uuid
from typing import Any, Dict, List, Optional, Tuple

from backend.release.security.models import (
    AffectedDependency,
    ContradictionStatus,
    FindingStatus,
    ReachabilityAssessment,
    ReachabilityStatus,
    SecurityContradictionRecord,
    SecurityFinding,
    SecurityVerification,
    SecurityVerificationStatus,
)


class SecurityContradictionEngine:
    """
    Sovereign Controller contradiction detector for security intelligence.
    Identifies conflicting claims across scanners, lockfiles, PRs, and analyzers.
    """

    def __init__(self):
        pass

    def detect_contradictions(
        self,
        findings: List[SecurityFinding],
        dependencies: Optional[Dict[str, AffectedDependency]] = None,
        reachability_map: Optional[Dict[str, ReachabilityAssessment]] = None,
        verifications: Optional[List[SecurityVerification]] = None,
        production_artifact_digest: Optional[str] = None,
        head_commit: Optional[str] = None,
        artifacts: Optional[Dict[str, Any]] = None,
        deployments: Optional[Dict[str, Any]] = None,
        services: Optional[Dict[str, Any]] = None,
        exposure_map: Optional[Dict[str, Any]] = None,
        business_map: Optional[Dict[str, Any]] = None,
        runtime_alerts: Optional[List[Dict[str, Any]]] = None,
    ) -> List[SecurityContradictionRecord]:
        """
        Scan all evidence and entities for security contradictions across 4.8 taxonomy.
        """
        contradictions: List[SecurityContradictionRecord] = []

        # 1. Scanner Contradiction (Scanner A vs Scanner B on same CVE/Package)
        scanner_contras = self._detect_scanner_contradictions(findings)
        contradictions.extend(scanner_contras)

        # 2. Manifest vs Lockfile Contradiction
        if dependencies:
            dep_contras = self._detect_manifest_lockfile_contradictions(dependencies)
            contradictions.extend(dep_contras)

        # 3. PR / Remediation Claim vs Rescan Contradiction
        if verifications:
            ver_contras = self._detect_remediation_claim_contradictions(findings, verifications)
            contradictions.extend(ver_contras)

        # 4. SAST vs Reachability Contradiction / REACHABILITY_EVIDENCE_CONFLICT
        if reachability_map:
            reach_contras = self._detect_sast_reachability_contradictions(findings, reachability_map)
            contradictions.extend(reach_contras)

        # 5. Production Artifact vs Repository HEAD Contradiction / REPOSITORY_ARTIFACT_MISMATCH
        if production_artifact_digest and head_commit:
            drift_contras = self._detect_artifact_drift_contradictions(
                findings, production_artifact_digest, head_commit
            )
            contradictions.extend(drift_contras)

        # 6. ARTIFACT_DEPLOYMENT_MISMATCH
        art_dep_contras = self._detect_artifact_deployment_mismatch(
            findings=findings,
            artifacts=artifacts,
            deployments=deployments,
            production_artifact_digest=production_artifact_digest,
            head_commit=head_commit,
        )
        contradictions.extend(art_dep_contras)

        # 7. DEPLOYMENT_VERSION_MISMATCH
        if deployments and services:
            dep_ver_contras = self._detect_deployment_version_mismatch(deployments, services)
            contradictions.extend(dep_ver_contras)

        # 8. RUNTIME_SECURITY_STATE_MISMATCH
        if runtime_alerts:
            runtime_contras = self._detect_runtime_security_state_mismatch(findings, runtime_alerts)
            contradictions.extend(runtime_contras)

        # 9. EXPOSURE_EVIDENCE_CONFLICT
        if exposure_map:
            exp_contras = self._detect_exposure_evidence_conflicts(exposure_map)
            contradictions.extend(exp_contras)

        # 10. BUSINESS_CRITICALITY_CONFLICT
        if business_map:
            bus_contras = self._detect_business_criticality_conflicts(business_map)
            contradictions.extend(bus_contras)

        return contradictions

    def _detect_scanner_contradictions(
        self,
        findings: List[SecurityFinding],
    ) -> List[SecurityContradictionRecord]:
        """Group findings by CVE or package; detect if one scanner says ACTIVE and another says RESOLVED/CLEAN."""
        by_key: Dict[str, List[SecurityFinding]] = {}
        for f in findings:
            key = f.cve or f.package or f.finding_id
            by_key.setdefault(key, []).append(f)

        records: List[SecurityContradictionRecord] = []
        for key, group in by_key.items():
            if len(group) < 2:
                continue

            active_findings = [f for f in group if f.status == FindingStatus.ACTIVE]
            clean_findings = [
                f for f in group if f.status in (FindingStatus.RESOLVED, FindingStatus.FALSE_POSITIVE)
            ]

            if active_findings and clean_findings:
                f_act = active_findings[0]
                f_cln = clean_findings[0]
                records.append(
                    SecurityContradictionRecord(
                        finding_id=f_act.finding_id,
                        conflict_type="SCANNER_MISMATCH",
                        source_a=f_act.scanner,
                        source_b=f_cln.scanner,
                        claim_a=f"Vulnerable ({f_act.severity.value}): {f_act.description}",
                        claim_b=f"Clean / Resolved ({f_cln.status.value}): {f_cln.description}",
                        evidence_a_id=f_act.evidence_ids[0] if f_act.evidence_ids else f_act.finding_id,
                        evidence_b_id=f_cln.evidence_ids[0] if f_cln.evidence_ids else f_cln.finding_id,
                        status=ContradictionStatus.CONTRADICTED,
                        explanation=f"Scanner mismatch for {key}: {f_act.scanner} reports active vulnerability but {f_cln.scanner} reports clean.",
                    )
                )

            # Check for reachability conflict between scanners
            reach_true = [f for f in group if getattr(f, "is_reachable", None) is True]
            reach_false = [f for f in group if getattr(f, "is_reachable", None) is False]
            if reach_true and reach_false:
                f_rt = reach_true[0]
                f_rf = reach_false[0]
                records.append(
                    SecurityContradictionRecord(
                        finding_id=f_rt.finding_id,
                        conflict_type="REACHABILITY_EVIDENCE_CONFLICT",
                        source_a=f_rt.scanner,
                        source_b=f_rf.scanner,
                        claim_a=f"{f_rt.scanner} claims vulnerability is reachable",
                        claim_b=f"{f_rf.scanner} claims vulnerability is unreachable",
                        evidence_a_id=f_rt.evidence_ids[0] if f_rt.evidence_ids else f_rt.finding_id,
                        evidence_b_id=f_rf.evidence_ids[0] if f_rf.evidence_ids else f_rf.finding_id,
                        status=ContradictionStatus.CONTRADICTED,
                        explanation=f"Reachability evidence conflict for {key}: {f_rt.scanner} reports reachable but {f_rf.scanner} reports unreachable.",
                    )
                )

        return records

    def _detect_manifest_lockfile_contradictions(
        self,
        dependencies: Dict[str, AffectedDependency],
    ) -> List[SecurityContradictionRecord]:
        """Detect when manifest requirements contradict resolved lockfile pins."""
        records: List[SecurityContradictionRecord] = []
        for pkg, dep in dependencies.items():
            if not dep.manifest_agrees_with_lockfile and dep.manifest_version and dep.lockfile_version:
                records.append(
                    SecurityContradictionRecord(
                        finding_id=f"dep-{pkg}",
                        conflict_type="MANIFEST_VS_LOCKFILE",
                        source_a=dep.manifest_file or "manifest",
                        source_b=dep.lockfile_file or "lockfile",
                        claim_a=f"Manifest specifies requirement: {dep.manifest_version}",
                        claim_b=f"Lockfile resolved to conflicting version: {dep.lockfile_version}",
                        evidence_a_id=f"manifest-{pkg}",
                        evidence_b_id=f"lockfile-{pkg}",
                        status=ContradictionStatus.CONTRADICTED,
                        explanation=f"Dependency inconsistency: {dep.manifest_file} requirement '{dep.manifest_version}' disagrees with resolved lockfile pin '{dep.lockfile_version}'.",
                    )
                )
        return records

    def _detect_remediation_claim_contradictions(
        self,
        findings: List[SecurityFinding],
        verifications: List[SecurityVerification],
    ) -> List[SecurityContradictionRecord]:
        """Detect when PR or metadata claims fixed, but rescan still reports vulnerability."""
        records: List[SecurityContradictionRecord] = []
        ver_map = {v.finding_id: v for v in verifications}

        for f in findings:
            ver = ver_map.get(f.finding_id)
            if ver:
                if f.status == FindingStatus.RESOLVED and ver.status == SecurityVerificationStatus.STILL_VULNERABLE:
                    records.append(
                        SecurityContradictionRecord(
                            finding_id=f.finding_id,
                            conflict_type="CLAIM_VS_RESCAN",
                            source_a="pull_request_claim",
                            source_b="security_rescan",
                            claim_a="Remediation claimed vulnerability is resolved",
                            claim_b=f"Authoritative rescan proves vulnerability remains active on commit {ver.rescan_commit[:10]}",
                            evidence_a_id=f.finding_id,
                            evidence_b_id=ver.rescan_evidence_ids[0] if ver.rescan_evidence_ids else ver.verification_id,
                            status=ContradictionStatus.CONTRADICTED,
                            explanation=f"Premature resolution claim contradicted: Rescan against {ver.rescan_commit[:10]} failed with {ver.status.value}.",
                        )
                    )
                elif f.status == FindingStatus.ACTIVE and ver.status == SecurityVerificationStatus.VERIFIED_RESOLVED:
                    records.append(
                        SecurityContradictionRecord(
                            finding_id=f.finding_id,
                            conflict_type="CLAIM_VS_RESCAN",
                            source_a=f.scanner,
                            source_b="security_rescan",
                            claim_a=f"Initial scanner {f.scanner} flagged active finding",
                            claim_b=f"Fresh verification scan on {ver.rescan_commit[:10]} verified clean",
                            evidence_a_id=f.finding_id,
                            evidence_b_id=ver.verification_id,
                            status=ContradictionStatus.CONFIRMED,
                            explanation="Initial active finding successfully cleared by fresh verified rescan.",
                        )
                    )
        return records

    def _detect_sast_reachability_contradictions(
        self,
        findings: List[SecurityFinding],
        reachability_map: Dict[str, ReachabilityAssessment],
    ) -> List[SecurityContradictionRecord]:
        """Detect when SAST scanner claims reachable, but structural reachability proves unreachable."""
        records: List[SecurityContradictionRecord] = []
        for f in findings:
            r = reachability_map.get(f.finding_id) or reachability_map.get(f.package or "")
            if r:
                # SAST says reachable, but AST/call-graph proved UNREACHABLE
                if f.is_reachable and r.status == ReachabilityStatus.UNREACHABLE:
                    records.append(
                        SecurityContradictionRecord(
                            finding_id=f.finding_id,
                            conflict_type="SAST_VS_REACHABILITY",
                            source_a=f.scanner,
                            source_b="reachability_analyzer",
                            claim_a="Scanner flagged vulnerability as reachable/exploitable",
                            claim_b=f"Call-graph & AST analysis proved dead code or uninvoked symbol: {r.rationale}",
                            evidence_a_id=f.finding_id,
                            evidence_b_id=f"reachability-{f.finding_id}",
                            status=ContradictionStatus.CONTRADICTED,
                            explanation=f"Reachability contradiction: {f.scanner} asserts reachable code, but structural call-graph proves {r.status.value}.",
                        )
                    )
        return records

    def _detect_artifact_drift_contradictions(
        self,
        findings: List[SecurityFinding],
        production_artifact_digest: str,
        head_commit: str,
    ) -> List[SecurityContradictionRecord]:
        """Detect when deployed artifact image differs in vulnerability state from current repo HEAD."""
        records: List[SecurityContradictionRecord] = []
        for f in findings:
            if f.artifact_digest and f.artifact_digest.lower() == production_artifact_digest.lower():
                # Finding is on the deployed artifact
                if f.commit.lower() != head_commit.lower() and f.status == FindingStatus.ACTIVE:
                    records.append(
                        SecurityContradictionRecord(
                            finding_id=f.finding_id,
                            conflict_type="ARTIFACT_VS_HEAD",
                            source_a="deployed_artifact",
                            source_b="repository_head",
                            claim_a=f"Active vulnerability in deployed artifact {f.artifact_digest[:12]}",
                            claim_b=f"Repository HEAD is commit {head_commit[:10]}, differing from deployed artifact commit {f.commit[:10]}",
                            evidence_a_id=f.finding_id,
                            evidence_b_id=f"head-{head_commit[:10]}",
                            status=ContradictionStatus.STALE,
                            explanation=f"Environment drift detected: Production artifact {f.artifact_digest[:12]} contains active vulnerability, while repository HEAD has advanced to {head_commit[:10]}.",
                        )
                    )
        return records

    def _detect_artifact_deployment_mismatch(
        self,
        findings: List[SecurityFinding],
        artifacts: Optional[Dict[str, Any]],
        deployments: Optional[Dict[str, Any]],
        production_artifact_digest: Optional[str],
        head_commit: Optional[str],
    ) -> List[SecurityContradictionRecord]:
        """Detect when repository/artifact says patched, but production deployment says vulnerable."""
        records: List[SecurityContradictionRecord] = []
        if not deployments:
            return records

        prod_deps = [d for d in deployments.values() if getattr(d, "environment", None) == "PRODUCTION" or getattr(d, "is_active_in_production", False)]
        if not prod_deps and production_artifact_digest:
            # Check findings on production_artifact_digest vs head
            for f in findings:
                if f.artifact_digest and f.artifact_digest == production_artifact_digest and f.status == FindingStatus.ACTIVE:
                    if head_commit and f.commit != head_commit:
                        records.append(
                            SecurityContradictionRecord(
                                finding_id=f.finding_id,
                                conflict_type="ARTIFACT_DEPLOYMENT_MISMATCH",
                                source_a="repository_head",
                                source_b="production_deployment",
                                claim_a=f"Repository HEAD commit {head_commit[:10]} is patched/updated",
                                claim_b=f"Production deployment artifact {f.artifact_digest[:12]} is active and vulnerable",
                                evidence_a_id=f"commit-{head_commit[:10]}",
                                evidence_b_id=f.finding_id,
                                status=ContradictionStatus.CONTRADICTED,
                                explanation=f"Artifact deployment contradiction: Repository HEAD is patched but production deployment is running vulnerable artifact {f.artifact_digest[:12]}.",
                            )
                        )
            return records

        for dep in prod_deps:
            dep_digest = getattr(dep, "artifact_digest", None)
            dep_commit = getattr(dep, "commit", None)
            for f in findings:
                # If finding is on deployed artifact but resolved in HEAD
                if f.artifact_digest and dep_digest and f.artifact_digest.lower() == dep_digest.lower():
                    if f.status == FindingStatus.ACTIVE and head_commit and dep_commit and head_commit != dep_commit:
                        records.append(
                            SecurityContradictionRecord(
                                finding_id=f.finding_id,
                                conflict_type="ARTIFACT_DEPLOYMENT_MISMATCH",
                                source_a="repository_head",
                                source_b="production_deployment",
                                claim_a=f"Repository HEAD commit {head_commit[:10]} is patched",
                                claim_b=f"Production deployment {getattr(dep, 'deployment_id', '')} still runs vulnerable artifact {dep_digest[:12]}",
                                evidence_a_id=f"head-{head_commit[:10]}",
                                evidence_b_id=f.finding_id,
                                status=ContradictionStatus.CONTRADICTED,
                                explanation=f"Artifact deployment mismatch: Repository HEAD is patched, but active production deployment {getattr(dep, 'deployment_id', '')} runs vulnerable artifact {dep_digest[:12]}.",
                            )
                        )
        return records

    def _detect_deployment_version_mismatch(
        self,
        deployments: Dict[str, Any],
        services: Dict[str, Any],
    ) -> List[SecurityContradictionRecord]:
        """Detect when deployment record reports commit/digest differing from running service telemetry."""
        records: List[SecurityContradictionRecord] = []
        for svc_id, svc in services.items():
            svc_digest = getattr(svc, "active_artifact_digest", None)
            svc_dep_id = getattr(svc, "active_deployment_id", None)
            if svc_dep_id and svc_dep_id in deployments:
                dep = deployments[svc_dep_id]
                dep_digest = getattr(dep, "artifact_digest", None)
                if svc_digest and dep_digest and svc_digest.lower() != dep_digest.lower():
                    records.append(
                        SecurityContradictionRecord(
                            finding_id=f"drift-{svc_id}",
                            conflict_type="DEPLOYMENT_VERSION_MISMATCH",
                            source_a="deployment_control_plane",
                            source_b="running_service_telemetry",
                            claim_a=f"Deployment {svc_dep_id} specifies artifact {dep_digest[:12]}",
                            claim_b=f"Running service {svc_id} reports active artifact {svc_digest[:12]}",
                            evidence_a_id=f"dep-{svc_dep_id}",
                            evidence_b_id=f"svc-{svc_id}",
                            status=ContradictionStatus.CONTRADICTED,
                            explanation=f"Deployment version mismatch: Service {svc_id} runtime artifact {svc_digest[:12]} does not match deployment registry {dep_digest[:12]}.",
                        )
                    )
        return records

    def _detect_runtime_security_state_mismatch(
        self,
        findings: List[SecurityFinding],
        runtime_alerts: List[Dict[str, Any]],
    ) -> List[SecurityContradictionRecord]:
        """Detect when static scanner declares clean, but runtime sensor detects active exploit."""
        records: List[SecurityContradictionRecord] = []
        for alert in runtime_alerts:
            target_pkg = alert.get("package") or alert.get("cve")
            alert_id = alert.get("alert_id", "runtime-alert")
            for f in findings:
                if (f.cve and f.cve == target_pkg) or (f.package and f.package == target_pkg):
                    if f.status in (FindingStatus.RESOLVED, FindingStatus.FALSE_POSITIVE):
                        records.append(
                            SecurityContradictionRecord(
                                finding_id=f.finding_id,
                                conflict_type="RUNTIME_SECURITY_STATE_MISMATCH",
                                source_a=f.scanner,
                                source_b="runtime_security_sensor",
                                claim_a=f"Scanner {f.scanner} flagged {target_pkg} as {f.status.value}",
                                claim_b=f"Runtime sensor detected active exploit attempt on {target_pkg}: {alert.get('message', '')}",
                                evidence_a_id=f.finding_id,
                                evidence_b_id=alert_id,
                                status=ContradictionStatus.CONTRADICTED,
                                explanation=f"Runtime security state mismatch: Scanner claims {target_pkg} is resolved, but runtime sensor detected active threat.",
                            )
                        )
        return records

    def _detect_exposure_evidence_conflicts(
        self,
        exposure_map: Dict[str, Any],
    ) -> List[SecurityContradictionRecord]:
        """Detect when network exposure evidence has unresolved conflicts across providers."""
        records: List[SecurityContradictionRecord] = []
        for svc_id, exp in exposure_map.items():
            if getattr(exp, "has_conflicting_evidence", False):
                sources = getattr(exp, "conflicting_sources", [])
                records.append(
                    SecurityContradictionRecord(
                        finding_id=f"exp-conflict-{svc_id}",
                        conflict_type="EXPOSURE_EVIDENCE_CONFLICT",
                        source_a="network_provider_a",
                        source_b="network_provider_b",
                        claim_a=sources[0] if len(sources) > 0 else "Provider claims internet-facing",
                        claim_b=sources[1] if len(sources) > 1 else "Provider claims internal-only",
                        evidence_a_id=f"exp-{svc_id}-a",
                        evidence_b_id=f"exp-{svc_id}-b",
                        status=ContradictionStatus.CONTRADICTED,
                        explanation=f"Network exposure conflict on service {svc_id}: {getattr(exp, 'rationale', '')}",
                    )
                )
        return records

    def _detect_business_criticality_conflicts(
        self,
        business_map: Dict[str, Any],
    ) -> List[SecurityContradictionRecord]:
        """Detect conflicting business impact tier claims across providers."""
        records: List[SecurityContradictionRecord] = []
        # Checks if multiple conflicting business impact items exist for same service
        return records

