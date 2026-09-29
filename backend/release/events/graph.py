"""
Enterprise Evidence Graph Domain Abstraction (Brick 4.3)

Maintains explicit relationship topology between enterprise entities, investigations,
evidence, and decisions.
Supports:
1. 17 Node Types & 17 Relationship Types.
2. Temporal validity: distinguishes active (currently valid) relationships from historical relationships.
3. Upstream and downstream graph traversals (e.g. from commit to affected releases, from decision to evidence).
4. Storage implementation decoupling: pure domain graph abstraction.
"""

from __future__ import annotations

import threading
import time
from enum import Enum
from typing import Any, Dict, List, Optional, Set
from pydantic import BaseModel, Field


class GraphNodeType(str, Enum):
    ORGANIZATION     = "Organization"
    REPOSITORY       = "Repository"
    SERVICE          = "Service"
    BRANCH           = "Branch"
    COMMIT           = "Commit"
    PULL_REQUEST     = "PullRequest"
    RELEASE          = "Release"
    WORK_ITEM        = "WorkItem"
    INCIDENT         = "Incident"
    SECURITY_FINDING = "SecurityFinding"
    CI_PIPELINE_RUN  = "CIPipelineRun"
    ENVIRONMENT      = "Environment"
    INVESTIGATION    = "Investigation"
    GAP              = "Gap"
    EVIDENCE         = "Evidence"
    DECISION         = "Decision"
    ACTION           = "Action"
    PERSON           = "Person"
    BUILD_ARTIFACT   = "BuildArtifact"
    DEPLOYMENT       = "Deployment"
    RUNTIME_SERVICE  = "RuntimeService"
    VULNERABILITY    = "Vulnerability"
    SECURITY_IMPACT  = "SecurityImpact"


class GraphEdgeType(str, Enum):
    CONTAINS       = "CONTAINS"
    OWNS           = "OWNS"
    CHANGED_BY     = "CHANGED_BY"
    BASED_ON       = "BASED_ON"
    TARGETS        = "TARGETS"
    LINKED_TO      = "LINKED_TO"
    DEPENDS_ON     = "DEPENDS_ON"
    BLOCKS         = "BLOCKS"
    AFFECTS        = "AFFECTS"
    GENERATED      = "GENERATED"
    SUPPORTS       = "SUPPORTS"
    CONTRADICTS    = "CONTRADICTS"
    SUPERSEDES     = "SUPERSEDES"
    RESOLVES       = "RESOLVES"
    TRIGGERS       = "TRIGGERS"
    EXECUTES       = "EXECUTES"
    VERIFIES       = "VERIFIES"
    REACHABLE_FROM = "REACHABLE_FROM"
    BUILT_AS       = "BUILT_AS"
    DEPLOYED_AS    = "DEPLOYED_AS"
    RUNS_AS        = "RUNS_AS"
    EXPOSED_BY     = "EXPOSED_BY"
    REMEDIATED_BY  = "REMEDIATED_BY"
    VERIFIED_BY    = "VERIFIED_BY"


class GraphNode(BaseModel):
    """Vertex in the Enterprise Evidence Graph."""
    node_id: str
    node_type: GraphNodeType
    tenant_id: str = "default"
    properties: Dict[str, Any] = Field(default_factory=dict)
    created_at: str = Field(default_factory=lambda: time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))


class GraphEdge(BaseModel):
    """Directed, typed edge in the Enterprise Evidence Graph."""
    edge_id: str
    from_node_id: str
    to_node_id: str
    edge_type: GraphEdgeType
    tenant_id: str = "default"
    properties: Dict[str, Any] = Field(default_factory=dict)
    created_at: str = Field(default_factory=lambda: time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
    valid_from: str = Field(default_factory=lambda: time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
    valid_until: Optional[str] = None
    is_active: bool = True
    confidence: float = 1.0


class EvidenceGraph:
    """
    Thread-safe in-memory domain abstraction of the Enterprise Evidence Graph.
    Can be backed by property graph or relational storage in subsequent bricks.
    """

    def __init__(self):
        self._nodes: Dict[str, GraphNode] = {}
        self._edges: Dict[str, GraphEdge] = {}  # edge_id -> edge
        self._outgoing: Dict[str, Set[str]] = {}  # from_node -> set of edge_ids
        self._incoming: Dict[str, Set[str]] = {}  # to_node -> set of edge_ids
        self._lock = threading.RLock()

    def add_node(
        self,
        node_id: str,
        node_type: GraphNodeType,
        properties: Optional[Dict[str, Any]] = None,
    ) -> GraphNode:
        """Add or update a node in the graph."""
        with self._lock:
            if node_id in self._nodes:
                if properties:
                    self._nodes[node_id].properties.update(properties)
                return self._nodes[node_id]

            node = GraphNode(
                node_id=node_id,
                node_type=node_type,
                properties=properties or {},
            )
            self._nodes[node_id] = node
            self._outgoing.setdefault(node_id, set())
            self._incoming.setdefault(node_id, set())
            return node

    def add_edge(
        self,
        from_node_id: str,
        to_node_id: str,
        edge_type: GraphEdgeType,
        properties: Optional[Dict[str, Any]] = None,
        is_active: bool = True,
        confidence: float = 1.0,
    ) -> GraphEdge:
        """Create a directed relationship between two entities."""
        edge_id = f"edge-{from_node_id}-{edge_type.value}-{to_node_id}"
        now_ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

        with self._lock:
            # Ensure nodes exist
            self._outgoing.setdefault(from_node_id, set())
            self._incoming.setdefault(to_node_id, set())

            edge = GraphEdge(
                edge_id=edge_id,
                from_node_id=from_node_id,
                to_node_id=to_node_id,
                edge_type=edge_type,
                properties=properties or {},
                valid_from=now_ts,
                is_active=is_active,
                confidence=confidence,
            )
            self._edges[edge_id] = edge
            self._outgoing[from_node_id].add(edge_id)
            self._incoming[to_node_id].add(edge_id)
            return edge

    def invalidate_edge(self, from_node_id: str, to_node_id: str, edge_type: GraphEdgeType) -> bool:
        """Mark relationship as historical / inactive (e.g. superseded commit binding)."""
        now_ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        edge_id = f"edge-{from_node_id}-{edge_type.value}-{to_node_id}"

        with self._lock:
            edge = self._edges.get(edge_id)
            if edge:
                edge.is_active = False
                edge.valid_until = now_ts
                return True
            return False

    def get_node(self, node_id: str) -> Optional[GraphNode]:
        with self._lock:
            return self._nodes.get(node_id)

    def get_edges(
        self,
        from_id: Optional[str] = None,
        to_id: Optional[str] = None,
        edge_type: Optional[GraphEdgeType] = None,
        active_only: bool = True,
        direction: Optional[str] = None,
        entity_id: Optional[str] = None,
    ) -> List[GraphEdge]:
        """Query edges matching criteria."""
        # Handle direction parameter if provided
        target = entity_id or from_id
        if direction:
            if direction.lower() == "out":
                from_id = target
                to_id = None
            elif direction.lower() == "in":
                to_id = target
                from_id = None
            elif direction.lower() == "both":
                from_edges = self.get_edges(from_id=target, edge_type=edge_type, active_only=active_only)
                to_edges = self.get_edges(to_id=target, edge_type=edge_type, active_only=active_only)
                seen_ids = set()
                combined: List[GraphEdge] = []
                for edge in from_edges + to_edges:
                    if edge.edge_id not in seen_ids:
                        seen_ids.add(edge.edge_id)
                        combined.append(edge)
                return combined

        with self._lock:
            candidates: List[GraphEdge] = []
            if from_id:
                edge_ids = self._outgoing.get(from_id, set())
                candidates = [self._edges[eid] for eid in edge_ids if eid in self._edges]
            elif to_id:
                edge_ids = self._incoming.get(to_id, set())
                candidates = [self._edges[eid] for eid in edge_ids if eid in self._edges]
            else:
                candidates = list(self._edges.values())

            results: List[GraphEdge] = []
            for e in candidates:
                if to_id and e.to_node_id != to_id:
                    continue
                if from_id and e.from_node_id != from_id:
                    continue
                if edge_type and e.edge_type != edge_type:
                    continue
                if active_only and not e.is_active:
                    continue
                results.append(e)

            return results

    def get_neighbors(
        self,
        node_id: str,
        direction: str = "outgoing",
        active_only: bool = True,
    ) -> List[GraphNode]:
        """Retrieve neighboring nodes."""
        with self._lock:
            target_ids: Set[str] = set()
            if direction in ("outgoing", "both"):
                for eid in self._outgoing.get(node_id, set()):
                    e = self._edges.get(eid)
                    if e and (not active_only or e.is_active):
                        target_ids.add(e.to_node_id)

            if direction in ("incoming", "both"):
                for eid in self._incoming.get(node_id, set()):
                    e = self._edges.get(eid)
                    if e and (not active_only or e.is_active):
                        target_ids.add(e.from_node_id)

            return [self._nodes[nid] for nid in target_ids if nid in self._nodes]

    @property
    def nodes(self) -> Dict[str, GraphNode]:
        with self._lock:
            return dict(self._nodes)

    @property
    def edges(self) -> List[GraphEdge]:
        with self._lock:
            return list(self._edges.values())

    def clear(self) -> None:
        with self._lock:
            self._nodes.clear()
            self._edges.clear()
            self._outgoing.clear()
            self._incoming.clear()
