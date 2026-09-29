"""
DAG Dependency & Topological State Propagation Subsystem for ORACLE (Brick 3.5B)

Provides rigorous graph validation (cycle detection, self-dependency rejection, nonexistent
gap rejection), deterministic diamond DAG evaluation, and dynamic replanning invalidation
and restoration cascades.
"""

from __future__ import annotations

import threading
from typing import Any, Dict, List, Optional, Set, Tuple
from pydantic import BaseModel, Field

from backend.investigation.models import GapStatus, InformationGap


class DAGValidationResult(BaseModel):
    """Result of DAG structural validation."""
    is_valid: bool
    error_type: Optional[str] = None
    error_message: Optional[str] = None
    cycle_path: Optional[List[str]] = None
    details: Dict[str, Any] = Field(default_factory=dict)


class DependencyGraph:
    """
    Authoritative DAG manager governing gap dependencies, cycle prevention,
    and topological state cascades.
    """

    def __init__(self):
        self._lock = threading.RLock()
        # dependent -> set of prerequisite gaps it depends on
        self._dependencies: Dict[str, Set[str]] = {}
        # prerequisite -> set of downstream dependent gaps
        self._dependents: Dict[str, Set[str]] = {}

    def get_prerequisites(self, gap_id: str) -> Set[str]:
        with self._lock:
            return set(self._dependencies.get(gap_id, set()))

    def get_dependents(self, gap_id: str) -> Set[str]:
        with self._lock:
            return set(self._dependents.get(gap_id, set()))

    def _find_path(self, start: str, target: str, visited: Optional[Set[str]] = None) -> Optional[List[str]]:
        """DFS to find if a directed path exists from start to target in the dependency graph."""
        if visited is None:
            visited = set()
        if start == target:
            return [start]
        visited.add(start)

        # Edges represent: gap -> prerequisite it depends on
        for neighbor in self._dependencies.get(start, set()):
            if neighbor not in visited:
                sub_path = self._find_path(neighbor, target, visited)
                if sub_path is not None:
                    return [start] + sub_path
        return None

    def validate_dependency(
        self,
        dependent_id: str,
        prerequisite_id: str,
        existing_gap_ids: Set[str],
    ) -> DAGValidationResult:
        """
        Validate proposed dependency edge before applying it.
        Strictly rejects:
        - Self dependencies (A -> A)
        - Nonexistent gaps (A or B not in existing_gap_ids)
        - Duplicate edges
        - Cycles (e.g. A -> B -> C -> A)
        """
        with self._lock:
            # 1. Nonexistent gap check
            if dependent_id not in existing_gap_ids:
                return DAGValidationResult(
                    is_valid=False,
                    error_type="NONEXISTENT_GAP",
                    error_message=f"Dependent gap '{dependent_id}' does not exist in investigation session.",
                    details={"gap_id": dependent_id},
                )
            if prerequisite_id not in existing_gap_ids:
                return DAGValidationResult(
                    is_valid=False,
                    error_type="NONEXISTENT_GAP",
                    error_message=f"Prerequisite gap '{prerequisite_id}' does not exist in investigation session.",
                    details={"gap_id": prerequisite_id},
                )

            # 2. Self-dependency check
            if dependent_id == prerequisite_id:
                return DAGValidationResult(
                    is_valid=False,
                    error_type="SELF_DEPENDENCY",
                    error_message=f"Self-dependency rejected: gap '{dependent_id}' cannot depend on itself.",
                    details={"gap_id": dependent_id},
                )

            # 3. Duplicate edge check
            if prerequisite_id in self._dependencies.get(dependent_id, set()):
                return DAGValidationResult(
                    is_valid=False,
                    error_type="DUPLICATE_EDGE",
                    error_message=f"Duplicate dependency: '{dependent_id}' already depends on '{prerequisite_id}'.",
                    details={"dependent_id": dependent_id, "prerequisite_id": prerequisite_id},
                )

            # 4. Cycle detection
            existing_path = self._find_path(prerequisite_id, dependent_id)
            if existing_path is not None:
                cycle = existing_path + [prerequisite_id]
                return DAGValidationResult(
                    is_valid=False,
                    error_type="CYCLE_DETECTED",
                    error_message=f"Cycle detected: adding edge '{dependent_id}' -> '{prerequisite_id}' creates cycle: {' -> '.join(cycle)}",
                    cycle_path=cycle,
                    details={"cycle": cycle},
                )

            return DAGValidationResult(is_valid=True)

    def add_dependency(
        self,
        dependent_id: str,
        prerequisite_id: str,
        existing_gap_ids: Set[str],
        gaps_map: Optional[Dict[str, InformationGap]] = None,
    ) -> DAGValidationResult:
        """
        Validate and register dependency edge.
        Updates internal graph and gap models.
        """
        with self._lock:
            val_res = self.validate_dependency(dependent_id, prerequisite_id, existing_gap_ids)
            if not val_res.is_valid:
                return val_res

            self._dependencies.setdefault(dependent_id, set()).add(prerequisite_id)
            self._dependents.setdefault(prerequisite_id, set()).add(dependent_id)

            if gaps_map:
                dep_gap = gaps_map.get(dependent_id)
                prereq_gap = gaps_map.get(prerequisite_id)
                if dep_gap and prerequisite_id not in dep_gap.depends_on_gap_ids:
                    dep_gap.depends_on_gap_ids.append(prerequisite_id)
                if prereq_gap and dependent_id not in prereq_gap.dependent_gap_ids:
                    prereq_gap.dependent_gap_ids.append(dependent_id)

                # Check if dependent should immediately transition to DEPENDENCY_UNSATISFIED
                if prereq_gap and prereq_gap.status != GapStatus.RESOLVED:
                    if dep_gap:
                        dep_gap.unsatisfied_prerequisites.append(prerequisite_id)
                        if dep_gap.status not in [GapStatus.RESOLVED, GapStatus.RECONCILIATION_REQUIRED]:
                            dep_gap.status = GapStatus.DEPENDENCY_UNSATISFIED

            return val_res

    def get_all_downstream(self, gap_id: str) -> List[str]:
        """Return all downstream dependent gaps in topological BFS/DFS order."""
        with self._lock:
            visited: Set[str] = set()
            queue = [gap_id]
            order: List[str] = []

            while queue:
                curr = queue.pop(0)
                for downstream in self._dependents.get(curr, set()):
                    if downstream not in visited:
                        visited.add(downstream)
                        order.append(downstream)
                        queue.append(downstream)
            return order

    def evaluate_gap_eligibility(
        self,
        gap_id: str,
        gaps_map: Dict[str, InformationGap],
    ) -> Tuple[bool, Set[str]]:
        """
        Deterministic diamond DAG evaluation.
        A gap is ONLY eligible (satisfied prerequisites) if ALL required prerequisites
        are in status GapStatus.RESOLVED.
        Returns: (is_eligible, set_of_unsatisfied_prerequisite_ids)
        """
        with self._lock:
            prereqs = self.get_prerequisites(gap_id)
            if not prereqs:
                return True, set()

            unsatisfied = set()
            for pid in prereqs:
                p_gap = gaps_map.get(pid)
                if not p_gap or p_gap.status != GapStatus.RESOLVED:
                    unsatisfied.add(pid)

            return (len(unsatisfied) == 0), unsatisfied

    def propagate_invalidation(
        self,
        invalidated_gap_id: str,
        gaps_map: Dict[str, InformationGap],
    ) -> List[str]:
        """
        Cascade invalidation down the DAG.
        When upstream gap fails or is reopened/rejected, all downstream dependents
        cascade into DEPENDENCY_UNSATISFIED and record unsatisfied prerequisites.
        """
        with self._lock:
            downstream = self.get_all_downstream(invalidated_gap_id)
            impacted: List[str] = []

            for gid in downstream:
                gap = gaps_map.get(gid)
                if not gap:
                    continue

                # Check if this downstream gap now has unsatisfied prerequisites
                is_eligible, unsatisfied = self.evaluate_gap_eligibility(gid, gaps_map)
                gap.unsatisfied_prerequisites = sorted(list(unsatisfied))

                if not is_eligible:
                    if gap.status != GapStatus.DEPENDENCY_UNSATISFIED:
                        gap.status = GapStatus.DEPENDENCY_UNSATISFIED
                        impacted.append(gid)

            return impacted

    def propagate_restoration(
        self,
        restored_gap_id: str,
        gaps_map: Dict[str, InformationGap],
    ) -> List[str]:
        """
        Topological restoration cascade.
        When restored_gap_id resolves:
        Downstream gaps are checked. A downstream gap leaves DEPENDENCY_UNSATISFIED
        and transitions to OPEN IF AND ONLY IF ALL of its prerequisites are resolved.
        In a diamond DAG (D depends on B and C), restoring B alone leaves D
        in DEPENDENCY_UNSATISFIED if C is still unresolved!
        """
        with self._lock:
            downstream = self.get_all_downstream(restored_gap_id)
            restored_gaps: List[str] = []

            for gid in downstream:
                gap = gaps_map.get(gid)
                if not gap:
                    continue

                is_eligible, unsatisfied = self.evaluate_gap_eligibility(gid, gaps_map)
                gap.unsatisfied_prerequisites = sorted(list(unsatisfied))

                if is_eligible:
                    # All prerequisites satisfied!
                    if gap.status == GapStatus.DEPENDENCY_UNSATISFIED:
                        gap.status = GapStatus.OPEN
                        restored_gaps.append(gid)
                else:
                    # Prerequisites still missing (e.g. other branch of diamond)
                    # MUST remain DEPENDENCY_UNSATISFIED
                    if gap.status != GapStatus.DEPENDENCY_UNSATISFIED:
                        gap.status = GapStatus.DEPENDENCY_UNSATISFIED

            return restored_gaps
