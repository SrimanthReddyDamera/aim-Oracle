"""
Multi-Node Worker Coordinator & Fencing Subsystem (Brick 4.5)

Coordinates multiple worker nodes operating against the shared persistence layer:
1. WorkerNode registration, heartbeat renewal, and dead-node detection.
2. Distributed task claiming with fencing token enforcement.
3. Task starvation prevention & graceful node draining/shutdown.
4. Fail-closed recovery when worker nodes crash or partition.
"""

from __future__ import annotations

import logging
import os
import socket
import threading
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional

from backend.release.distributed.lock import DistributedLockProvider, InMemoryDistributedLockProvider, LockToken
from backend.release.workers.lease import TaskStatus, WorkerLeaseManager, WorkerTask

logger = logging.getLogger("oracle.distributed.coordinator")


class NodeStatus(str, Enum):
    STARTING = "STARTING"
    ACTIVE   = "ACTIVE"
    DRAINING = "DRAINING"
    DEAD     = "DEAD"


@dataclass
class WorkerNode:
    """Metadata for an active or recorded worker process/node."""
    node_id: str
    host: str
    pid: int
    started_at: str
    last_heartbeat: float
    status: NodeStatus = NodeStatus.STARTING
    claimed_task_ids: List[str] = field(default_factory=list)


class DistributedWorkerCoordinator:
    """
    Coordinates distributed worker processes across nodes.
    Ensures safe task ownership, fencing tokens, and dead-node reclamation.
    """

    def __init__(
        self,
        store_or_lock: Any = None,
        lock_provider: Optional[DistributedLockProvider] = None,
        heartbeat_interval_seconds: float = 5.0,
        node_timeout_seconds: float = 20.0,
        node_id: Optional[str] = None,
    ):
        if isinstance(store_or_lock, DistributedLockProvider):
            self.lock_provider = store_or_lock
            self.store = None
        else:
            self.store = store_or_lock
            self.lock_provider = lock_provider or InMemoryDistributedLockProvider()

        self.heartbeat_interval = heartbeat_interval_seconds
        self.node_timeout = node_timeout_seconds
        self.node_id = node_id or f"node-{socket.gethostname()}-{os.getpid()}-{uuid.uuid4().hex[:6]}"

        self.current_node = WorkerNode(
            node_id=self.node_id,
            host=socket.gethostname(),
            pid=os.getpid(),
            started_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            last_heartbeat=time.time(),
            status=NodeStatus.ACTIVE,
        )

        self._nodes: Dict[str, WorkerNode] = {}
        self._lock = threading.RLock()
        self._running = False
        self._heartbeat_thread: Optional[threading.Thread] = None

    def register_node(self, node_id: str, hostname: str = "localhost", pid: int = 0) -> WorkerNode:
        """Register or heartbeat an active worker node."""
        with self._lock:
            node = WorkerNode(
                node_id=node_id,
                host=hostname,
                pid=pid,
                started_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                last_heartbeat=time.time(),
                status=NodeStatus.ACTIVE,
            )
            self._nodes[node_id] = node
            return node

    def list_nodes(self) -> List[WorkerNode]:
        """List all registered worker nodes."""
        with self._lock:
            return list(self._nodes.values())

    def get_node(self, node_id: str) -> Optional[WorkerNode]:
        """Get registered node by id."""
        with self._lock:
            return self._nodes.get(node_id)

    def detect_dead_nodes(self, timeout_seconds: Optional[float] = None) -> List[str]:
        """Audit active nodes and mark unresponsive nodes as DEAD."""
        timeout = timeout_seconds if timeout_seconds is not None else self.node_timeout
        now = time.time()
        dead_nodes = []
        with self._lock:
            for nid, node in list(self._nodes.items()):
                if node.status == NodeStatus.ACTIVE and (now - node.last_heartbeat) > timeout:
                    node.status = NodeStatus.DEAD
                    dead_nodes.append(nid)

        if dead_nodes and self.store and hasattr(self.store, "leases") and self.store.leases:
            logger.warning(f"Detected dead worker nodes: {dead_nodes}. Reclaiming leases.")
            self.store.leases.reclaim_expired_leases()
        return dead_nodes

    def claim_task(
        self,
        task_id: str,
        node_id: str,
        ttl_seconds: float = 30.0,
        tenant_id: str = "default",
    ) -> Optional[LockToken]:
        """Claim a specific task lock with distributed fencing token for a node."""
        with self._lock:
            node = self._nodes.get(node_id)
            if not node or node.status != NodeStatus.ACTIVE:
                return None
            token = self.lock_provider.acquire(
                key=f"task:{task_id}",
                owner=node_id,
                ttl_seconds=ttl_seconds,
                tenant_id=tenant_id,
            )
            if token:
                node.claimed_task_ids.append(task_id)
            return token

    def recover_task_lease(
        self,
        task_id: str,
        new_owner: str,
        ttl_seconds: float = 30.0,
        tenant_id: str = "default",
    ) -> Optional[LockToken]:
        """Recover an abandoned or expired task lease, advancing fencing token monotonically."""
        token = self.lock_provider.acquire(
            key=f"task:{task_id}",
            owner=new_owner,
            ttl_seconds=ttl_seconds,
            tenant_id=tenant_id,
        )
        if token:
            with self._lock:
                node = self._nodes.get(new_owner)
                if node:
                    node.claimed_task_ids.append(task_id)
        return token

    def start(self) -> None:
        """Start node coordinator and background heartbeat loop."""
        with self._lock:
            if self._running:
                return
            self._running = True
            if self.node_id not in self._nodes:
                self._nodes[self.node_id] = self.current_node
            self.current_node.status = NodeStatus.ACTIVE
            self.current_node.last_heartbeat = time.time()
            self._heartbeat_thread = threading.Thread(
                target=self._heartbeat_loop,
                name=f"coordinator-hb-{self.node_id}",
                daemon=True,
            )
            self._heartbeat_thread.start()
            logger.info(f"Worker node {self.node_id} started coordinator loop.")

    def stop(self) -> None:
        """Gracefully drain and stop worker node coordinator."""
        with self._lock:
            self.current_node.status = NodeStatus.DRAINING
            self._running = False
        if self._heartbeat_thread and self._heartbeat_thread.is_alive():
            self._heartbeat_thread.join(timeout=2.0)
        logger.info(f"Worker node {self.node_id} stopped coordinator loop.")

    def heartbeat(self) -> None:
        """Refresh current node heartbeat and reclaim dead nodes."""
        now = time.time()
        with self._lock:
            self.current_node.last_heartbeat = now
            if self.node_id in self._nodes:
                self._nodes[self.node_id].last_heartbeat = now

        self.detect_dead_nodes()

    def claim_task_with_fencing(
        self,
        task_types: Optional[List[str]] = None,
        lease_duration_seconds: int = 30,
        tenant_id: str = "default",
    ) -> Optional[tuple[Dict[str, Any], Optional[LockToken]]]:
        """
        Claim next available task from durable store, securing distributed lock with fencing token.
        Guarantees that two worker nodes cannot execute the same task.
        """
        # 1. Claim task in database
        task_dict = self.store.leases.claim_next_task(
            worker_id=self.node_id,
            task_types=task_types,
            lease_duration_seconds=lease_duration_seconds,
        )
        if not task_dict:
            return None

        task_id = task_dict["task_id"]

        # 2. Acquire distributed lock with fencing token for task
        lock_token = self.lock_provider.acquire(
            key=f"task:{task_id}",
            owner=self.node_id,
            ttl_seconds=float(lease_duration_seconds),
            tenant_id=tenant_id,
        )

        with self._lock:
            self.current_node.claimed_task_ids.append(task_id)

        return task_dict, lock_token

    def complete_task(
        self,
        task_id: str,
        lock_token: Optional[LockToken] = None,
    ) -> None:
        """Complete task and release distributed lock."""
        self.store.leases.complete_task(task_id)
        if lock_token:
            self.lock_provider.release(lock_token)

        with self._lock:
            if task_id in self.current_node.claimed_task_ids:
                self.current_node.claimed_task_ids.remove(task_id)

    def fail_task(
        self,
        task_id: str,
        error_message: str,
        lock_token: Optional[LockToken] = None,
    ) -> None:
        """Fail task with error and release lock."""
        self.store.leases.fail_task(task_id, error_message=error_message)
        if lock_token:
            self.lock_provider.release(lock_token)

        with self._lock:
            if task_id in self.current_node.claimed_task_ids:
                self.current_node.claimed_task_ids.remove(task_id)

    def is_fencing_token_valid(self, lock_token: LockToken) -> bool:
        """Verify worker holds the most current fencing token before mutating state."""
        current_highest = self.lock_provider.get_current_fencing_token(
            lock_token.key,
            tenant_id=lock_token.tenant_id,
        )
        return lock_token.fencing_token >= current_highest and not lock_token.is_expired

    def _heartbeat_loop(self) -> None:
        while self._running:
            try:
                self.heartbeat()
            except Exception as e:
                logger.error(f"Error in coordinator heartbeat loop: {e}")
            time.sleep(self.heartbeat_interval)
