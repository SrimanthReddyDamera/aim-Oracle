"""
ORACLE 5.1 — Regression Suite Runner

Executes regression test suites inside the isolated sandbox environment,
parses test results (collected, passed, failed, skipped), and captures
unabridged terminal output and telemetry.
"""

from __future__ import annotations

import re
from typing import Dict, Optional, Tuple

from backend.sandbox.isolation import IsolatedSandboxWorkspace
from backend.sandbox.models import ExecutionRecord


class RegressionRunner:
    """
    Executes regression tests inside the sandbox and parses test outcomes.
    """

    def __init__(
        self,
        command: str = "pytest tests/ -v",
        timeout: float = 60.0,
    ):
        self.command = command
        self.timeout = timeout

    def run(
        self,
        sandbox: IsolatedSandboxWorkspace,
        custom_command: Optional[str] = None,
    ) -> Tuple[ExecutionRecord, Dict[str, int], bool]:
        """
        Runs the regression command inside the sandbox.
        Returns:
            (ExecutionRecord, summary_counts, is_passed)
        """
        cmd = custom_command or self.command
        record = sandbox.run_command(cmd, timeout=self.timeout)

        summary = self._parse_pytest_summary(record.stdout, record.stderr)
        is_passed = (record.exit_code == 0) and (summary.get("failed", 0) == 0)

        return record, summary, is_passed

    @staticmethod
    def _parse_pytest_summary(stdout: str, stderr: str) -> Dict[str, int]:
        """
        Extracts test counts from pytest stdout or stderr output.
        Example line: '==== 5 passed, 1 failed, 2 skipped in 0.42s ===='
        """
        counts = {
            "collected": 0,
            "passed": 0,
            "failed": 0,
            "skipped": 0,
            "errors": 0,
        }
        text = f"{stdout}\n{stderr}"

        # Pytest pattern: '(\d+) passed' or '(\d+) failed' etc.
        passed_m = re.search(r"(\d+)\s+passed", text)
        if passed_m:
            counts["passed"] = int(passed_m.group(1))

        failed_m = re.search(r"(\d+)\s+failed", text)
        if failed_m:
            counts["failed"] = int(failed_m.group(1))

        skipped_m = re.search(r"(\d+)\s+skipped", text)
        if skipped_m:
            counts["skipped"] = int(skipped_m.group(1))

        errors_m = re.search(r"(\d+)\s+error", text)
        if errors_m:
            counts["errors"] = int(errors_m.group(1))

        collected_m = re.search(r"collected\s+(\d+)\s+item", text)
        if collected_m:
            counts["collected"] = int(collected_m.group(1))
        else:
            counts["collected"] = counts["passed"] + counts["failed"] + counts["skipped"] + counts["errors"]

        return counts
