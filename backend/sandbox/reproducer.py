"""
ORACLE 5.1 — Reproducer Engine & Negative Proof

Orchestrates negative proof execution:
1. BEFORE PATCH: Runs reproducer test/command to empirically confirm failure condition reproduces.
2. AFTER PATCH: Runs reproducer test/command to empirically confirm failure condition is eliminated.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional, Tuple

from backend.sandbox.isolation import IsolatedSandboxWorkspace
from backend.sandbox.models import ExecutionRecord


class ReproducerRunner:
    """
    Executes reproducer tests inside the isolated sandbox to establish negative proof.
    """

    def __init__(
        self,
        command: str = "pytest tests/ -k test_reproduce",
        expected_error: Optional[str] = None,
        timeout: float = 30.0,
    ):
        self.command = command
        self.expected_error = expected_error
        self.timeout = timeout

    def run_pre_patch(
        self,
        sandbox: IsolatedSandboxWorkspace,
        reproducer_script: Optional[str] = None,
        script_path: str = "tests/reproduce_issue.py",
    ) -> ExecutionRecord:
        """
        Executes reproducer on pristine unpatched snapshot.
        Failure must be observed (exit_code != 0 or expected error observed).
        """
        if reproducer_script:
            full_path = sandbox.workspace_dir / script_path
            full_path.parent.mkdir(parents=True, exist_ok=True)
            full_path.write_text(reproducer_script, encoding="utf-8")

        record = sandbox.run_command(self.command, timeout=self.timeout)

        # Confirm failure was reproduced
        is_reproduced = False
        if record.exit_code != 0:
            is_reproduced = True
        elif self.expected_error and (
            self.expected_error in record.stdout or self.expected_error in record.stderr
        ):
            is_reproduced = True

        record.reproduced_failure = is_reproduced
        return record

    def run_post_patch(
        self,
        sandbox: IsolatedSandboxWorkspace,
    ) -> ExecutionRecord:
        """
        Executes reproducer on patched repository.
        Must succeed cleanly (exit_code == 0).
        """
        record = sandbox.run_command(self.command, timeout=self.timeout)
        # For post-patch, failure eliminated means clean exit code 0
        record.reproduced_failure = (record.exit_code != 0)
        return record

    def evaluate_negative_proof(
        self,
        pre_record: ExecutionRecord,
        post_record: ExecutionRecord,
    ) -> bool:
        """
        Negative proof passes if:
        1. Pre-patch reproduced the bug (exit_code != 0 or reproduced_failure == True)
        2. Post-patch executed cleanly (exit_code == 0)
        """
        pre_failed = (pre_record.exit_code != 0) or (pre_record.reproduced_failure is True)
        post_passed = (post_record.exit_code == 0) and (post_record.reproduced_failure is not True)
        return pre_failed and post_passed
