"""
Repository Security Sandbox & Resource Limiter (ORACLE 5.0 - Step 2)

Enforces strict filesystem and boundary security:
1. Path validation: Restricts repository access to explicitly permitted workspace roots.
2. Traversal prevention: Resolves real paths, blocking '../' and symlink escapes.
3. Resource boundaries: Guards against unbounded scans, gigantic files, and resource exhaustion.
4. Secret redaction: Automatically identifies and scrubs tokens, keys, passwords, and credentials.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from backend.core.security import redact_sensitive_data, redact_sensitive_text

logger = logging.getLogger("oracle.repository.security")


class SecurityValidationError(PermissionError):
    """Raised when repository path or access violates security boundaries."""
    pass


class ResourceLimitExceededError(ValueError):
    """Raised when repository size, file count, or analysis duration exceeds safe boundaries."""
    pass


class RepositorySecuritySandbox:
    """
    Guards repository intake and ensures zero host file leakage or unbounded resource consumption.
    """

    DEFAULT_MAX_FILES = 1000
    DEFAULT_MAX_FILE_SIZE = 1 * 1024 * 1024  # 1 MB
    DEFAULT_MAX_TOTAL_BYTES = 25 * 1024 * 1024  # 25 MB
    DEFAULT_MAX_GIT_COMMITS = 50
    DEFAULT_MAX_ANALYSIS_SECONDS = 15.0
    DEFAULT_MAX_LOG_SIZE = 2 * 1024 * 1024  # 2 MB

    def __init__(
        self,
        allowed_roots: Optional[List[str | Path]] = None,
        max_files: int = DEFAULT_MAX_FILES,
        max_file_size: int = DEFAULT_MAX_FILE_SIZE,
        max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES,
        max_git_commits: int = DEFAULT_MAX_GIT_COMMITS,
        max_analysis_seconds: float = DEFAULT_MAX_ANALYSIS_SECONDS,
        max_log_size: int = DEFAULT_MAX_LOG_SIZE,
    ):
        self.max_files = max_files
        self.max_file_size = max_file_size
        self.max_total_bytes = max_total_bytes
        self.max_git_commits = max_git_commits
        self.max_analysis_seconds = max_analysis_seconds
        self.max_log_size = max_log_size

        # By default, allow the current project root and subdirectories
        project_root = Path(__file__).resolve().parent.parent.parent
        self.allowed_roots: List[Path] = [project_root.resolve()]

        if allowed_roots:
            for r in allowed_roots:
                p = Path(r).resolve()
                if p.exists() and p.is_dir():
                    self.allowed_roots.append(p)

    def add_allowed_root(self, root: str | Path) -> None:
        p = Path(root).resolve()
        if p.exists() and p.is_dir() and p not in self.allowed_roots:
            self.allowed_roots.append(p)

    def validate_repository_path(self, raw_path: str | Path) -> Path:
        """
        Validates that raw_path points to an existing directory inside an allowed root,
        resolving all symlinks and ensuring no traversal escape.
        """
        if not raw_path:
            raise SecurityValidationError("Repository path cannot be empty")

        p_str = str(raw_path).strip()
        if "\x00" in p_str:
            raise SecurityValidationError("Null byte detected in repository path")

        path_obj = Path(p_str)
        # Check if relative path was given, resolve against current working directory or first allowed root
        if not path_obj.is_absolute():
            resolved = (self.allowed_roots[0] / path_obj).resolve()
        else:
            resolved = path_obj.resolve()

        if not resolved.exists():
            raise SecurityValidationError(f"Repository path does not exist: {resolved}")

        if not resolved.is_dir():
            raise SecurityValidationError(f"Repository path is not a directory: {resolved}")

        # Check if resolved path is contained in at least one allowed root
        is_allowed = False
        for allowed in self.allowed_roots:
            try:
                resolved.relative_to(allowed)
                is_allowed = True
                break
            except ValueError:
                continue

        if not is_allowed:
            logger.warning(f"Rejected repository path {resolved} - not inside allowed roots: {self.allowed_roots}")
            raise SecurityValidationError(
                f"Repository path '{raw_path}' is outside permitted workspace roots."
            )

        return resolved

    def validate_file_access(self, root: Path, relative_file: str) -> Path:
        """
        Validates that a relative file path stays strictly inside root.
        """
        clean = relative_file.lstrip("/\\")
        target = (root / clean).resolve()
        try:
            target.relative_to(root)
        except ValueError:
            raise SecurityValidationError(f"Path traversal detected: {relative_file}")

        if target.exists() and target.is_file():
            size = target.stat().st_size
            if size > self.max_file_size:
                raise ResourceLimitExceededError(
                    f"File '{relative_file}' size ({size} bytes) exceeds maximum limit of {self.max_file_size} bytes"
                )

        return target

    def redact_content(self, text: str) -> str:
        """Sanitize secrets, keys, and tokens from any text artifact."""
        return redact_sensitive_text(text)

    def redact_data(self, data: Any) -> Any:
        """Recursively sanitize structured dictionary or list data."""
        return redact_sensitive_data(data)
