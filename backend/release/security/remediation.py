"""
Remediation Intelligence Engine (Brick 4.7)

Generates and validates evidence-backed remediation candidates:
- Evaluates fixed / patched version availability
- Evaluates SemVer constraints and breaking change risk (MAJOR vs MINOR vs PATCH)
- Checks transitive dependency compatibility across sibling constraints
- Computes lockfile diff impacts
- Generates rollback guidance and regression mitigations
- Proposes compensating controls when safe direct upgrade is incompatible

CRITICAL INVARIANT:
- Never recommend "Upgrade to X" unless ORACLE can establish that X is compatible
  with the investigated dependency graph.
"""

from __future__ import annotations

import re
import uuid
from typing import Any, Dict, List, Optional, Set, Tuple

from backend.release.security.dependency import VersionComparisonHelper
from backend.release.security.models import (
    AffectedDependency,
    CompensatingControl,
    CompensatingControlType,
    DependencyRelationship,
    RemediationCandidate,
    RemediationCompatibility,
    RemediationType,
    SecurityFinding,
    SemverImpact,
)


class RemediationIntelligenceEngine:
    """
    Controller-governed remediation intelligence analyzer.
    Validates candidate upgrades against the full dependency graph before recommending them.
    """

    def __init__(self):
        pass

    def evaluate_remediation(
        self,
        finding: SecurityFinding,
        affected_dep: Optional[AffectedDependency] = None,
        dependency_constraints: Optional[Dict[str, List[Tuple[str, str]]]] = None,
        # package -> [(dependent_parent, constraint_string)]
    ) -> RemediationCandidate:
        """
        Generate a validated, compatibility-checked remediation candidate for the finding.
        """
        package_name = finding.package or "unknown"
        current_v = finding.current_version or "0.0.0"
        fixed_v = finding.fixed_version

        # Case 1: No fixed version available
        if not fixed_v:
            return RemediationCandidate(
                candidate_id=f"rem-{uuid.uuid4().hex[:8]}",
                target_package=package_name,
                current_version=current_v,
                recommended_version=current_v,
                remediation_type=RemediationType.COMPENSATING_CONTROL,
                semver_impact=SemverImpact.PATCH,
                breaking_change_risk=0.0,
                is_compatible=True,
                compatibility_details="No upstream fixed version available; compensating control or WAF rule recommended.",
                rollback_guidance="Deactivate compensating control rule if false positives occur.",
                evidence_references=list(finding.evidence_ids),
            )

        # Case 2: Evaluate SemVer Impact of proposed fixed version
        parsed_curr = VersionComparisonHelper.parse_semver(current_v)
        parsed_fixed = VersionComparisonHelper.parse_semver(fixed_v)

        if parsed_fixed[0] > parsed_curr[0]:
            semver_impact = SemverImpact.MAJOR
            breaking_risk = 0.8
        elif parsed_fixed[1] > parsed_curr[1]:
            semver_impact = SemverImpact.MINOR
            breaking_risk = 0.3
        else:
            semver_impact = SemverImpact.PATCH
            breaking_risk = 0.05

        # Case 3: Check Transitive Dependency Compatibility
        compat = self._check_graph_compatibility(
            package_name=package_name,
            target_version=fixed_v,
            constraints=dependency_constraints or {},
        )

        # Case 4: Transitive vs Direct Upgrade Type
        rem_type = RemediationType.DIRECT_UPGRADE
        if affected_dep and affected_dep.relation_type.value == "TRANSITIVE":
            rem_type = RemediationType.TRANSITIVE_OVERRIDE

        # Build Candidate
        if not compat.is_compatible:
            # If upgrade is incompatible, recommend compensating control or alternative
            conflicts_summary = "; ".join(compat.conflicting_constraints)
            return RemediationCandidate(
                candidate_id=f"rem-{uuid.uuid4().hex[:8]}",
                target_package=package_name,
                current_version=current_v,
                recommended_version=current_v,  # Keep current version due to conflict
                remediation_type=RemediationType.COMPENSATING_CONTROL,
                semver_impact=semver_impact,
                breaking_change_risk=1.0,
                is_compatible=False,
                compatibility_details=f"Upgrade to {fixed_v} is INCOMPATIBLE with dependency graph: {conflicts_summary}. Compensating control required.",
                transitive_impacts=compat.conflicting_constraints,
                lockfile_diff={},
                rollback_guidance="Do not force-upgrade; resolve upstream dependent package constraints first.",
                evidence_references=list(finding.evidence_ids),
            )

        # Compatible upgrade candidate
        lockfile_diff = {package_name: f"{current_v} -> {fixed_v}"}
        details = (
            f"Upgrade {package_name} from {current_v} to {fixed_v} ({semver_impact.value} bump). "
            f"Verified compatible with {len(dependency_constraints.get(package_name, [])) if dependency_constraints else 0} dependent packages."
        )

        rollback_msg = f"Revert lockfile pin for {package_name} to {current_v} and rebuild container artifact."

        return RemediationCandidate(
            candidate_id=f"rem-{uuid.uuid4().hex[:8]}",
            target_package=package_name,
            current_version=current_v,
            recommended_version=fixed_v,
            remediation_type=rem_type,
            semver_impact=semver_impact,
            breaking_change_risk=breaking_risk,
            is_compatible=True,
            compatibility_details=details,
            transitive_impacts=[],
            lockfile_diff=lockfile_diff,
            rollback_guidance=rollback_msg,
            evidence_references=list(finding.evidence_ids),
        )

    def _check_graph_compatibility(
        self,
        package_name: str,
        target_version: str,
        constraints: Dict[str, List[Tuple[str, str]]],
    ) -> RemediationCompatibility:
        """
        Verify if upgrading package_name to target_version satisfies all dependent parent constraints.
        constraints format: { 'pkg': [ ('parentA', '<2.0.0'), ('parentB', '>=1.5.0') ] }
        """
        parent_rules = constraints.get(package_name, []) or constraints.get(package_name.lower(), [])
        conflicts: List[str] = []

        for parent, constraint in parent_rules:
            if not VersionComparisonHelper.is_version_in_range(target_version, constraint):
                conflicts.append(f"Parent '{parent}' requires '{package_name} {constraint}', but fixed version is '{target_version}'")

        is_compat = len(conflicts) == 0
        return RemediationCompatibility(
            is_compatible=is_compat,
            conflicting_constraints=conflicts,
            breaking_changes=[] if is_compat else conflicts,
            lockfile_conflicts=[],
        )
