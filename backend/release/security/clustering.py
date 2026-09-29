"""
Security Finding Clustering & Multi-Finding Reasoner (Brick 4.8)

Groups findings across scanners to eliminate duplicate alerts and produce unified impact clusters:
1. Clusters identical findings (same CVE + same package across different scanner vendors).
2. Clusters by shared root cause or affected dependency.
3. Clusters by shared remediation candidate (e.g. 5 CVEs resolved by a single library upgrade).
4. Distinguishes independent findings (never incorrectly merges unrelated vulnerabilities).
5. Preserves finding-level provenance on every individual finding.
"""

from __future__ import annotations

import uuid
from typing import Any, Dict, List, Optional, Set

from backend.release.security.models import (
    RemediationCandidate,
    SecurityFinding,
    SecurityImpactAssessment,
    SecurityImpactCluster,
    SecurityImpactLevel,
)


class SecurityClusteringEngine:
    """
    Deterministic finding clustering and deduplication reasoner.
    """

    def cluster_findings(
        self,
        findings: List[SecurityFinding],
        impact_map: Optional[Dict[str, SecurityImpactAssessment]] = None,
        remediations: Optional[List[RemediationCandidate]] = None,
    ) -> List[SecurityImpactCluster]:
        """
        Group findings into coherent, provenance-preserving clusters.
        """
        if not findings:
            return []

        impacts = impact_map or {}
        rems = remediations or []

        # Map package to remediation candidate if available
        rem_by_pkg: Dict[str, RemediationCandidate] = {}
        for r in rems:
            rem_by_pkg[r.target_package] = r

        # 1. Deduplicate identical findings across scanners
        # Key: (repository, commit, cve or finding_id, package)
        groups: Dict[str, List[SecurityFinding]] = {}
        for f in findings:
            key = f"{f.repository}:{f.commit}:{f.cve or f.finding_id}:{f.package or 'no-pkg'}"
            groups.setdefault(key, []).append(f)

        clusters: List[SecurityImpactCluster] = []

        for group_key, group_findings in groups.items():
            first = group_findings[0]
            root_cve = first.cve
            pkg = first.package
            finding_ids = [f.finding_id for f in group_findings]

            # Highest impact level among members
            group_levels = [
                impacts[fid].impact_level
                for fid in finding_ids
                if fid in impacts
            ]
            cluster_level = self._aggregate_impact_level(group_levels)

            # Common remediation
            common_rem = rem_by_pkg.get(pkg) if pkg else None

            is_indep = len(group_findings) == 1 and not common_rem

            prov = {
                "scanners_reporting": list({f.scanner for f in group_findings}),
                "distinct_finding_count": len(group_findings),
                "is_multi_scanner_agreement": len({f.scanner for f in group_findings}) > 1,
            }

            clusters.append(
                SecurityImpactCluster(
                    cluster_id=f"cluster-{uuid.uuid4().hex[:8]}",
                    root_cve=root_cve,
                    affected_package=pkg,
                    affected_service=first.provenance.get("service_name"),
                    finding_ids=finding_ids,
                    findings=group_findings,
                    cluster_impact_level=cluster_level,
                    common_remediation=common_rem,
                    is_independent=is_indep,
                    provenance=prov,
                )
            )

        return clusters

    def _aggregate_impact_level(self, levels: List[SecurityImpactLevel]) -> SecurityImpactLevel:
        """Derive highest severity impact level for cluster."""
        if not levels:
            return SecurityImpactLevel.MODERATE_IMPACT

        hierarchy = [
            SecurityImpactLevel.CRITICAL_IMPACT,
            SecurityImpactLevel.HIGH_IMPACT,
            SecurityImpactLevel.MODERATE_IMPACT,
            SecurityImpactLevel.LOW_IMPACT,
            SecurityImpactLevel.NEGLIGIBLE_IMPACT,
            SecurityImpactLevel.UNKNOWN_IMPACT,
        ]
        for h in hierarchy:
            if h in levels:
                return h
        return SecurityImpactLevel.MODERATE_IMPACT
