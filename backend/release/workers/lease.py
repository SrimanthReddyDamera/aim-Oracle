"""
Worker Lease & Claim Model (Brick 4.4)

Implements distributed task ownership, heartbeats, dead-worker recovery,
and retryable execution semantics.
"""

from __future__ import annotations

import logging
import time
import uuid
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional

from backend.release.persistence.interfaces import WorkerLeaseRepository

logger = logging.getLogger("oracle.workers.lease")


class TaskStatus(str, Enum):
    PENDING = "PENDING"
    CLAIMED = "CLAIMED"
    RUNNING = "RUNNING"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    RETRYABLE = "RETRYABLE"
    ABANDONED = "ABANDONED"


@dataclass
class WorkerTask:
    task_id: str
    task_type: str
    payload: Dict[str, Any]
    worker_id: str
    attempt_count: int
    lease_until: str
    tenant_id: str = "default"


class WorkerLeaseManager:
    """Manages worker claims, heartbeats, and task recovery."""

    def __init__(
        self,
        lease_repo: WorkerLeaseRepository,
        worker_id: Optional[str] = None,
        default_lease_duration: int = 30,
    ):
        self.repo = lease_repo
        self.worker_id = worker_id or f"worker-{uuid.uuid4().hex[:6]}"
        self.default_lease_duration = default_lease_duration

    def create_task(
        self,
        task_type: str,
        payload: Dict[str, Any],
        task_id: Optional[str] = None,
        tenant_id: str = "default",
    ) -> str:
        tid = task_id or f"task-{uuid.uuid4().hex[:8]}"
        self.repo.create_task(tid, task_type, payload, tenant_id=tenant_id)
        return tid

    def claim_task(
        self,
        task_types: Optional[List[str]] = None,
        lease_duration_seconds: Optional[int] = None,
    ) -> Optional[WorkerTask]:
        duration = lease_duration_seconds or self.default_lease_duration
        claimed_dict = self.repo.claim_next_task(
            worker_id=self.worker_id,
            task_types=task_types,
            lease_duration_seconds=duration,
        )
        if not claimed_dict:
            return None

        return WorkerTask(
            task_id=claimed_dict["task_id"],
            task_type=claimed_dict["task_type"],
            payload=claimed_dict["payload"],
            worker_id=self.worker_id,
            attempt_count=claimed_dict["attempt_count"],
            lease_until=claimed_dict["lease_until"],
        )

    def heartbeat(self, task_id: str, extension_seconds: Optional[int] = None) -> bool:
        ext = extension_seconds or self.default_lease_duration
        return self.repo.heartbeat_lease(task_id, self.worker_id, ext)

    def complete_task(self, task_id: str, result: Optional[Dict[str, Any]] = None) -> bool:
        return self.repo.complete_task(task_id, self.worker_id, result)

    def fail_task(
        self,
        task_id: str,
        error_message: str,
        retryable: bool = True,
        max_retries: int = 3,
    ) -> bool:
        return self.repo.fail_task(task_id, self.worker_id, error_message, retryable, max_retries)

    def reclaim_expired_leases(self, now_iso: Optional[str] = None) -> int:
        ts = now_iso or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        return self.repo.reclaim_expired_leases(ts)

    def get_task(self, task_id: str) -> Optional[Dict[str, Any]]:
        return self.repo.get_task(task_id)
