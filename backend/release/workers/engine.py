"""
Asynchronous Worker Engine (Brick 4.4)

Decouples ingestion from processing via durable worker task loops.
Executes event impact analysis, DAG re-investigation, and decision recalculation.
"""

from __future__ import annotations

import logging
import threading
import time
from typing import Any, Callable, Dict, List, Optional

from backend.release.workers.lease import WorkerLeaseManager, WorkerTask

logger = logging.getLogger("oracle.workers.engine")


class AsyncWorkerEngine:
    """Task processing engine running on leased durable work items."""

    def __init__(
        self,
        lease_manager: WorkerLeaseManager,
        poll_interval: float = 0.5,
    ):
        self.lease_manager = lease_manager
        self.poll_interval = poll_interval
        self._handlers: Dict[str, Callable[[WorkerTask], Any]] = {}
        self._running = False
        self._thread: Optional[threading.Thread] = None

    def register_handler(self, task_type: str, handler: Callable[[WorkerTask], Any]) -> None:
        """Register a processing callback for a specific task type."""
        self._handlers[task_type] = handler

    def process_one(self, task_types: Optional[List[str]] = None) -> bool:
        """
        Attempt to claim and process a single task.
        Returns True if a task was claimed and processed, False otherwise.
        """
        task = self.lease_manager.claim_task(task_types=task_types)
        if not task:
            return False

        handler = self._handlers.get(task.task_type)
        if not handler:
            logger.warning(f"No handler registered for task type '{task.task_type}'")
            self.lease_manager.fail_task(
                task.task_id,
                f"No handler registered for task type '{task.task_type}'",
                retryable=False,
            )
            return True

        try:
            logger.info(f"Worker '{self.lease_manager.worker_id}' executing task '{task.task_id}' ({task.task_type})")
            result = handler(task)
            result_dict = result if isinstance(result, dict) else {"status": "SUCCESS"}
            self.lease_manager.complete_task(task.task_id, result_dict)
            return True
        except Exception as exc:
            logger.error(f"Task '{task.task_id}' failed: {exc}", exc_info=True)
            self.lease_manager.fail_task(
                task.task_id,
                str(exc),
                retryable=True,
                max_retries=3,
            )
            return True

    def start_background(self) -> None:
        """Start worker loop in a background daemon thread."""
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        """Stop background worker loop."""
        self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.0)

    def _run_loop(self) -> None:
        while self._running:
            try:
                processed = self.process_one()
                if not processed:
                    time.sleep(self.poll_interval)
            except Exception as e:
                logger.error(f"Error in worker engine loop: {e}", exc_info=True)
                time.sleep(self.poll_interval)
