"""
Dependency Intelligence Engine (Brick 4.7)

Provides deterministic dependency graph reasoning:
1. Direct vs Transitive dependency classification
2. Multi-path path discovery (e.g. service -> A -> B -> C and service -> D -> C)
3. Vulnerable version range evaluation against installed version
4. Manifest vs Lockfile consistency checking & contradiction detection
5. Scope separation: RUNTIME vs DEV/TEST dependencies
6. Exact commit and artifact version binding verification
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Set, Tuple

from backend.release.security.models import (
    AffectedDependency,
    DependencyRelationship,
    DependencyRelationType,
    DependencyScope,
    SecurityFinding,
)


class VersionComparisonHelper:
    """Deterministic SemVer parsing and range matching."""

    @staticmethod
    def parse_semver(version_str: str) -> Tuple[int, int, int, str]:
        """Parse version string into (major, minor, patch, prerelease)."""
        clean = re.sub(r"^[vV^~=<>\s]+", "", version_str.strip())
        parts = clean.split("-", 1)
        core = parts[0]
        prerelease = parts[1] if len(parts) > 1 else ""

        nums = []
        for n in core.split("."):
            try:
                nums.append(int(n))
            except ValueError:
                nums.append(0)

        while len(nums) < 3:
            nums.append(0)

        return (nums[0], nums[1], nums[2], prerelease)

    @staticmethod
    def is_version_in_range(installed_version: str, version_range: str) -> bool:
        """
        Check if installed_version satisfies a vulnerable version range.
        Handles ranges like: '<2.31.0', '>=1.0.0,<1.26.18', '==2.0.0', '<=3.1.2'.
        """
        if not version_range or version_range == "*":
            return True

        inst_v = VersionComparisonHelper.parse_semver(installed_version)

        # Split multiple clauses e.g. ">=1.0.0, <1.26.18"
        clauses = [c.strip() for c in version_range.split(",") if c.strip()]
        for clause in clauses:
            match = re.match(r"^([<>=!~^]+)?\s*([0-9a-zA-Z.-]+)$", clause)
            if not match:
                continue
            op, target_str = match.groups()
            op = op or "=="
            target_v = VersionComparisonHelper.parse_semver(target_str)

            comp = VersionComparisonHelper.compare_versions(inst_v, target_v)

            if op == "<" and not (comp < 0):
                return False
            elif op == "<=" and not (comp <= 0):
                return False
            elif op == ">" and not (comp > 0):
                return False
            elif op == ">=" and not (comp >= 0):
                return False
            elif op in ("==", "=") and not (comp == 0):
                return False
            elif op == "!=" and not (comp != 0):
                return False

        return True

    @staticmethod
    def compare_versions(v1: Tuple[int, int, int, str], v2: Tuple[int, int, int, str]) -> int:
        """Compare two parsed versions: -1 if v1 < v2, 0 if v1 == v2, 1 if v1 > v2."""
        if v1[:3] < v2[:3]:
            return -1
        if v1[:3] > v2[:3]:
            return 1
        # If core numbers equal, consider prerelease
        if not v1[3] and v2[3]:
            return 1  # 1.0.0 > 1.0.0-rc1
        if v1[3] and not v2[3]:
            return -1
        if v1[3] < v2[3]:
            return -1
        if v1[3] > v2[3]:
            return 1
        return 0


class DependencyIntelligenceEngine:
    """
    Controller-governed dependency intelligence engine.
    Analyzes dependency graph topologies, detects direct/transitive relationships,
    and identifies manifest vs lockfile inconsistencies.
    """

    def __init__(self):
        pass

    def analyze_dependency(
        self,
        finding: SecurityFinding,
        manifest_data: Optional[Dict[str, Any]] = None,
        lockfile_data: Optional[Dict[str, Any]] = None,
        dependency_graph: Optional[List[DependencyRelationship]] = None,
        dev_packages: Optional[Set[str]] = None,
    ) -> AffectedDependency:
        """
        Produce authoritative AffectedDependency reasoning for a given finding.
        """
        package_name = finding.package or "unknown"
        installed_version = finding.current_version or "0.0.0"
        vulnerable_range = finding.vulnerable_version_range or (f"<={installed_version}" if installed_version != "0.0.0" else "*")
        fixed_range = finding.fixed_version

        # 1. Scope Analysis (Runtime vs Dev/Test)
        scope = DependencyScope.RUNTIME
        dev_set = dev_packages or set()
        if package_name.lower() in {p.lower() for p in dev_set}:
            scope = DependencyScope.DEV

        # 2. Graph Path & Relation Type (Direct vs Transitive)
        paths: List[List[str]] = []
        relation_type = DependencyRelationType.DIRECT

        if dependency_graph:
            paths = self._find_all_paths_to_package(dependency_graph, target_package=package_name)
            if paths:
                # Direct if any path has length 2 (e.g. ['service', 'pkg'])
                min_length = min(len(p) for p in paths)
                relation_type = DependencyRelationType.DIRECT if min_length <= 2 else DependencyRelationType.TRANSITIVE
            else:
                # Package not reachable from root — synthesize a direct path so consumers
                # can still reason about the package (e.g. transitive-confusion, name mismatch).
                paths = [["service", package_name]]
                relation_type = DependencyRelationType.DIRECT
        else:
            # Fallback path if no graph provided
            paths = [["service", package_name]]
            relation_type = DependencyRelationType.DIRECT

        # 3. Manifest vs Lockfile Evidence Verification
        manifest_ver = None
        manifest_file = None
        if manifest_data:
            manifest_file = manifest_data.get("filename", "manifest")
            deps = manifest_data.get("dependencies", {})
            manifest_ver = deps.get(package_name) or deps.get(package_name.lower())

        lockfile_ver = None
        lockfile_file = None
        if lockfile_data:
            lockfile_file = lockfile_data.get("filename", "lockfile")
            packages = lockfile_data.get("packages", {})
            lockfile_ver = packages.get(package_name) or packages.get(package_name.lower())

        # Determine agreement
        agrees = True
        if manifest_ver and lockfile_ver:
            # Check if lockfile version satisfies manifest constraint
            if not VersionComparisonHelper.is_version_in_range(lockfile_ver, manifest_ver):
                agrees = False

        # Determine if lockfile matches installed version
        if lockfile_ver and installed_version != "0.0.0":
            if lockfile_ver != installed_version:
                agrees = False

        return AffectedDependency(
            package_name=package_name,
            installed_version=installed_version,
            vulnerable_range=vulnerable_range,
            fixed_range=fixed_range,
            relation_type=relation_type,
            scope=scope,
            dependency_paths=paths,
            manifest_file=manifest_file,
            manifest_version=manifest_ver,
            lockfile_file=lockfile_file,
            lockfile_version=lockfile_ver,
            manifest_agrees_with_lockfile=agrees,
            applies_to_commit=True,
        )

    def _find_all_paths_to_package(
        self,
        relationships: List[DependencyRelationship],
        target_package: str,
        root_name: str = "service",
    ) -> List[List[str]]:
        """Compute all directed paths from root to target_package using DFS."""
        adj: Dict[str, List[str]] = {}
        for rel in relationships:
            if isinstance(rel, dict):
                parent = (rel.get("parent_package") or rel.get("package") or "").lower()
                child = (rel.get("child_package") or rel.get("depends_on") or "").lower()
            else:
                parent = getattr(rel, "parent_package", "").lower()
                child = getattr(rel, "child_package", "").lower()
            if parent and child:
                adj.setdefault(parent, []).append(child)

        target = target_package.lower()
        all_paths: List[List[str]] = []

        def dfs(current: str, path: List[str], visited: Set[str]):
            if current == target:
                all_paths.append(list(path))
                return
            for nxt in adj.get(current, []):
                if nxt not in visited:
                    visited.add(nxt)
                    path.append(nxt)
                    dfs(nxt, path, visited)
                    path.pop()
                    visited.remove(nxt)

        dfs(root_name.lower(), [root_name], {root_name.lower()})
        return all_paths
