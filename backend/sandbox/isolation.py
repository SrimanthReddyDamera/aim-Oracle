"""
ORACLE 5.1 — Sandbox Isolation & Execution Environment

Provides hardened execution isolation:
- Ephemeral workspace creation and guaranteed cleanup.
- Environment sanitization: Strips cloud tokens, database URLs, and API secrets.
- Network isolation: Enforces network disabled mode via proxy blackholing and environment tags.
- Watchdog execution: Enforces timeouts and captures stdout/stderr streams.
- Path confinement: Prevents symlink and directory traversal escape.
"""

from __future__ import annotations

import os
import shutil
import stat
import subprocess
import tempfile
import time
import uuid
from pathlib import Path
from typing import Dict, List, Optional, Union

from backend.sandbox.models import ExecutionRecord, FailureReason


# Environment variable keys that MUST NEVER leak into the sandbox
FORBIDDEN_ENV_PREFIXES = (
    "AWS_",
    "AZURE_",
    "GCP_",
    "GOOGLE_",
    "GITHUB_",
    "GITLAB_",
    "DOCKER_",
    "KUBERNETES_",
    "SECRET",
    "TOKEN",
    "PASSWORD",
    "PRIVATE_KEY",
    "DATABASE_",
    "DB_",
    "REDIS_URL",
    "DATABASE_URL",
)


def _handle_remove_readonly(func, path, exc_info):
    """Clear the readonly bit and retry removal (Windows file permission handling)."""
    try:
        os.chmod(path, stat.S_IWRITE)
        func(path)
    except Exception:
        pass


class IsolatedSandboxWorkspace:
    """
    Context manager managing the lifecycle of an ephemeral isolated sandbox workspace.
    Guarantees cleanup on normal completion, exceptions, timeouts, or cancellations.
    """

    def __init__(
        self,
        base_dir: Optional[Union[str, Path]] = None,
        sandbox_id: Optional[str] = None,
        network_enabled: bool = False,
    ):
        self.sandbox_id = sandbox_id or f"sbx_{uuid.uuid4().hex[:12]}"
        self.network_enabled = network_enabled
        self._custom_base = Path(base_dir) if base_dir else None
        self.workspace_dir: Optional[Path] = None
        self.is_active = False

    def __enter__(self) -> "IsolatedSandboxWorkspace":
        if self._custom_base:
            self._custom_base.mkdir(parents=True, exist_ok=True)
            self.workspace_dir = self._custom_base / self.sandbox_id
        else:
            temp_root = Path(tempfile.gettempdir()) / "oracle_sandboxes"
            temp_root.mkdir(parents=True, exist_ok=True)
            self.workspace_dir = temp_root / self.sandbox_id

        self.workspace_dir.mkdir(parents=True, exist_ok=True)
        self.is_active = True
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.cleanup()

    def cleanup(self) -> bool:
        """Destroy the sandbox workspace and all contents."""
        self.is_active = False
        if self.workspace_dir and self.workspace_dir.exists():
            try:
                shutil.rmtree(self.workspace_dir, onerror=_handle_remove_readonly)
                return True
            except Exception:
                return False
        return True

    def sanitize_environment(self, extra_env: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        """
        Builds a sanitized environment dictionary excluding all credentials and setting
        network isolation parameters.
        """
        clean_env: Dict[str, str] = {}

        # Preserve essential OS & Python runtime variables
        safe_keys = {
            "PATH",
            "SYSTEMROOT",
            "WINDIR",
            "COMSPEC",
            "PATHEXT",
            "TEMP",
            "TMP",
            "PYTHONPATH",
            "PYTHONHOME",
            "PYTHONIOENCODING",
            "LANG",
            "LC_ALL",
            "TERM",
        }

        for key, val in os.environ.items():
            upper_k = key.upper()
            # Exclude forbidden credentials
            if any(upper_k.startswith(p) for p in FORBIDDEN_ENV_PREFIXES):
                continue
            if "KEY" in upper_k or "SECRET" in upper_k or "TOKEN" in upper_k:
                continue

            if key in safe_keys or upper_k in safe_keys:
                clean_env[key] = val

        # Enforce sandbox markers
        clean_env["ORACLE_SANDBOX_ID"] = self.sandbox_id
        clean_env["ORACLE_SANDBOX_ACTIVE"] = "1"
        clean_env["PYTHONDONTWRITEBYTECODE"] = "1"
        clean_env["PYTHONUNBUFFERED"] = "1"

        # Network isolation
        if not self.network_enabled:
            clean_env["NETWORK_MODE"] = "DISABLED"
            # Route HTTP/HTTPS traffic to non-existent blackhole loopback port
            clean_env["HTTP_PROXY"] = "http://127.0.0.1:9"
            clean_env["HTTPS_PROXY"] = "http://127.0.0.1:9"
            clean_env["ALL_PROXY"] = "http://127.0.0.1:9"
            clean_env["NO_PROXY"] = ""

        if extra_env:
            for k, v in extra_env.items():
                upper_k = k.upper()
                if not any(upper_k.startswith(p) for p in FORBIDDEN_ENV_PREFIXES):
                    clean_env[k] = v

        return clean_env

    def validate_path_confinement(self, target_path: Union[str, Path]) -> Path:
        """
        Ensures a path resolves within the sandbox workspace.
        Raises PermissionError on path traversal or symlink escape.
        """
        if not self.workspace_dir or not self.workspace_dir.exists():
            raise RuntimeError("Sandbox workspace is not active")

        sandbox_root = self.workspace_dir.resolve()
        resolved = (sandbox_root / target_path).resolve()

        try:
            resolved.relative_to(sandbox_root)
        except ValueError:
            raise PermissionError(
                f"Path traversal escape detected: '{target_path}' escapes sandbox root '{sandbox_root}'"
            )

        return resolved

    def run_command(
        self,
        command: Union[str, List[str]],
        timeout: float = 30.0,
        cwd: Optional[Union[str, Path]] = None,
        extra_env: Optional[Dict[str, str]] = None,
    ) -> ExecutionRecord:
        """
        Executes an isolated command inside the sandbox workspace with strict timeouts.
        Captures exit code, stdout, stderr, and duration.
        """
        if not self.workspace_dir or not self.workspace_dir.exists():
            raise RuntimeError("Cannot execute in inactive sandbox")

        effective_cwd = Path(cwd) if cwd else self.workspace_dir
        if not effective_cwd.is_absolute():
            effective_cwd = (self.workspace_dir / effective_cwd).resolve()

        # Confinement check
        self.validate_path_confinement(effective_cwd)

        clean_env = self.sanitize_environment(extra_env)

        # Set PYTHONPATH so sandbox files can import project packages
        existing_py = clean_env.get("PYTHONPATH", "")
        clean_env["PYTHONPATH"] = f"{effective_cwd}{os.pathsep}{existing_py}" if existing_py else str(effective_cwd)

        start_time = time.time()
        now_str = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

        cmd_str = command if isinstance(command, str) else " ".join(command)

        try:
            proc = subprocess.Popen(
                command,
                cwd=str(effective_cwd),
                env=clean_env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                shell=isinstance(command, str),
            )

            try:
                stdout, stderr = proc.communicate(timeout=timeout)
                exit_code = proc.returncode
            except subprocess.TimeoutExpired:
                proc.kill()
                stdout, stderr = proc.communicate()
                duration = time.time() - start_time
                return ExecutionRecord(
                    command=cmd_str,
                    exit_code=-1,
                    stdout=stdout or "",
                    stderr=(stderr or "") + f"\n[ORACLE WATCHDOG] Command timed out after {timeout} seconds.",
                    duration_seconds=round(duration, 3),
                    timestamp=now_str,
                )

            duration = time.time() - start_time
            return ExecutionRecord(
                command=cmd_str,
                exit_code=exit_code,
                stdout=stdout or "",
                stderr=stderr or "",
                duration_seconds=round(duration, 3),
                timestamp=now_str,
            )

        except Exception as exc:
            duration = time.time() - start_time
            return ExecutionRecord(
                command=cmd_str,
                exit_code=-1,
                stdout="",
                stderr=f"Failed to execute command: {exc}",
                duration_seconds=round(duration, 3),
                timestamp=now_str,
            )
