"""
Repository Adapter Abstraction & Local Git Implementation (ORACLE 5.0)

Provides a vendor-agnostic repository interface so the investigation engine
does not couple directly to filesystem or provider implementation details.
Designed to support future providers (GitHub, GitLab, Bitbucket, Cloud workspace)
while cleanly executing on the local filesystem today.
"""

from __future__ import annotations

import abc
import json
import logging
import os
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("oracle.repository.adapter")


class RepositoryAdapter(abc.ABC):
    """
    Abstract contract for repository inspection and content retrieval.
    All path arguments are relative to the repository root unless explicitly noted.
    """

    @property
    @abc.abstractmethod
    def root_path(self) -> Path:
        """Return the resolved base root path of the repository."""
        raise NotImplementedError

    @abc.abstractmethod
    def file_exists(self, relative_path: str) -> bool:
        """Check if a file exists relative to the repository root."""
        raise NotImplementedError

    @abc.abstractmethod
    def read_file(
        self,
        relative_path: str,
        start_line: Optional[int] = None,
        end_line: Optional[int] = None,
    ) -> str:
        """
        Read content of a file, optionally bounded by 1-indexed line numbers.
        Returns normalized UTF-8 string.
        """
        raise NotImplementedError

    @abc.abstractmethod
    def read_file_lines(
        self,
        relative_path: str,
        start_line: int,
        end_line: int,
    ) -> List[Tuple[int, str]]:
        """
        Read a slice of lines returning list of (line_number, line_content).
        """
        raise NotImplementedError

    @abc.abstractmethod
    def list_files(
        self,
        subpath: str = "",
        extensions: Optional[List[str]] = None,
        ignore_patterns: Optional[List[str]] = None,
        max_files: int = 1000,
    ) -> List[str]:
        """List relative file paths within the repository obeying filters and bounds."""
        raise NotImplementedError

    @abc.abstractmethod
    def get_git_commit(self, commit_hash: str) -> Optional[Dict[str, Any]]:
        """Retrieve structured metadata for a specific git commit."""
        raise NotImplementedError

    @abc.abstractmethod
    def get_recent_commits(
        self,
        file_path: Optional[str] = None,
        limit: int = 10,
    ) -> List[Dict[str, Any]]:
        """Retrieve recent commits, optionally filtered to those modifying a specific file."""
        raise NotImplementedError

    @abc.abstractmethod
    def get_git_diff(
        self,
        commit_hash: Optional[str] = None,
        file_path: Optional[str] = None,
    ) -> str:
        """Retrieve unified diff for a commit or working tree against parent."""
        raise NotImplementedError

    @abc.abstractmethod
    def get_git_blame(
        self,
        file_path: str,
        line: int,
    ) -> Optional[Dict[str, Any]]:
        """Retrieve blame attribution (commit, author, timestamp) for a specific line."""
        raise NotImplementedError

    @abc.abstractmethod
    def find_tests(self, target_file: Optional[str] = None) -> List[str]:
        """Locate test files related to the target file or general test directory."""
        raise NotImplementedError

    @abc.abstractmethod
    def get_repository_metadata(self) -> Dict[str, Any]:
        """Return structural repository metadata (commit, branch, remotes, root)."""
        raise NotImplementedError


class LocalGitRepositoryAdapter(RepositoryAdapter):
    """
    Local filesystem and Git implementation of RepositoryAdapter.
    Executes deterministic git commands with timeouts and fallbacks.
    """

    DEFAULT_IGNORE_DIRS = {
        ".git", "node_modules", "venv", ".venv", "__pycache__",
        "dist", "build", "coverage", "target", ".pytest_cache",
        ".mypy_cache", ".tox", ".idea", ".vscode", "storage"
    }

    def __init__(self, root_path: str | Path):
        self._root = Path(root_path).resolve()
        if not self._root.exists() or not self._root.is_dir():
            raise ValueError(f"Repository root directory does not exist: {self._root}")

    @property
    def root_path(self) -> Path:
        return self._root

    def _resolve_safe_path(self, relative_path: str) -> Path:
        """Resolve a relative path, strictly guarding against root escape."""
        clean = relative_path.lstrip("/\\")
        resolved = (self._root / clean).resolve()
        try:
            resolved.relative_to(self._root)
        except ValueError:
            raise PermissionError(f"Path traversal detected: {relative_path} attempts to escape repository root")
        return resolved

    def file_exists(self, relative_path: str) -> bool:
        try:
            p = self._resolve_safe_path(relative_path)
            return p.exists() and p.is_file()
        except Exception:
            return False

    def read_file(
        self,
        relative_path: str,
        start_line: Optional[int] = None,
        end_line: Optional[int] = None,
    ) -> str:
        p = self._resolve_safe_path(relative_path)
        if not p.is_file():
            raise FileNotFoundError(f"File not found in repository: {relative_path}")

        try:
            with open(p, "r", encoding="utf-8", errors="replace") as f:
                if start_line is None and end_line is None:
                    return f.read()
                lines = f.readlines()
        except Exception as e:
            logger.error(f"Failed reading file {relative_path}: {e}")
            raise

        s = max(0, (start_line - 1) if start_line is not None else 0)
        e = min(len(lines), end_line if end_line is not None else len(lines))
        return "".join(lines[s:e])

    def read_file_lines(
        self,
        relative_path: str,
        start_line: int,
        end_line: int,
    ) -> List[Tuple[int, str]]:
        p = self._resolve_safe_path(relative_path)
        if not p.is_file():
            return []

        with open(p, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()

        s = max(1, start_line)
        e = min(len(lines), end_line)
        result = []
        for idx in range(s, e + 1):
            result.append((idx, lines[idx - 1].rstrip("\r\n")))
        return result

    def list_files(
        self,
        subpath: str = "",
        extensions: Optional[List[str]] = None,
        ignore_patterns: Optional[List[str]] = None,
        max_files: int = 1000,
    ) -> List[str]:
        target_dir = self._resolve_safe_path(subpath) if subpath else self._root
        if not target_dir.is_dir():
            return []

        ext_set = set(e.lower() for e in extensions) if extensions else None
        ignore_set = self.DEFAULT_IGNORE_DIRS.union(set(ignore_patterns or []))

        results: List[str] = []
        for root, dirs, files in os.walk(target_dir):
            # Modify dirs in-place to avoid descending into ignored directories
            dirs[:] = [d for d in dirs if d not in ignore_set and not d.startswith(".")]

            for file in sorted(files):
                if ext_set:
                    ext = Path(file).suffix.lower()
                    if ext not in ext_set:
                        continue

                full_path = Path(root) / file
                rel = full_path.relative_to(self._root).as_posix()
                results.append(rel)

                if len(results) >= max_files:
                    logger.warning(f"File discovery reached max_files limit of {max_files}")
                    return results

        return sorted(results)

    def _run_git(self, args: List[str], timeout_sec: float = 5.0) -> Optional[str]:
        """Execute git CLI within repository root safely."""
        try:
            proc = subprocess.run(
                ["git"] + args,
                cwd=str(self._root),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=timeout_sec,
                encoding="utf-8",
                errors="replace",
            )
            if proc.returncode == 0:
                return proc.stdout.strip()
            logger.debug(f"Git command failed: {' '.join(args)}: {proc.stderr}")
            return None
        except (subprocess.SubprocessError, FileNotFoundError, OSError) as e:
            logger.debug(f"Git execution error for {' '.join(args)}: {e}")
            return None

    def get_git_commit(self, commit_hash: str) -> Optional[Dict[str, Any]]:
        raw = self._run_git([
            "show",
            "--no-patch",
            "--format=%H%n%an%n%ae%n%aI%n%s",
            commit_hash,
        ])
        if not raw:
            return None
        parts = raw.split("\n", 4)
        if len(parts) >= 5:
            return {
                "hash": parts[0],
                "author_name": parts[1],
                "author_email": parts[2],
                "date": parts[3],
                "message": parts[4],
            }
        return {"hash": commit_hash, "raw": raw}

    def get_recent_commits(
        self,
        file_path: Optional[str] = None,
        limit: int = 10,
    ) -> List[Dict[str, Any]]:
        args = [
            "log",
            f"-n{limit}",
            "--format=%H%x1f%an%x1f%ae%x1f%aI%x1f%s",
        ]
        if file_path:
            args.extend(["--", file_path])

        raw = self._run_git(args)
        if not raw:
            return []

        commits = []
        for line in raw.split("\n"):
            line = line.strip()
            if not line:
                continue
            fields = line.split("\x1f")
            if len(fields) >= 5:
                commits.append({
                    "hash": fields[0],
                    "author_name": fields[1],
                    "author_email": fields[2],
                    "date": fields[3],
                    "message": fields[4],
                })
        return commits

    def get_git_diff(
        self,
        commit_hash: Optional[str] = None,
        file_path: Optional[str] = None,
    ) -> str:
        args = ["diff"]
        if commit_hash:
            args.append(f"{commit_hash}~1..{commit_hash}")
        else:
            args.append("HEAD~1..HEAD")

        if file_path:
            args.extend(["--", file_path])

        diff_out = self._run_git(args)
        return diff_out or ""

    def get_git_blame(
        self,
        file_path: str,
        line: int,
    ) -> Optional[Dict[str, Any]]:
        raw = self._run_git([
            "blame",
            "-L", f"{line},{line}",
            "--porcelain",
            file_path,
        ])
        if not raw:
            return None

        lines = raw.split("\n")
        commit_hash = lines[0].split()[0] if lines else "unknown"
        author = "unknown"
        author_time = ""
        summary = ""

        for l in lines[1:]:
            if l.startswith("author "):
                author = l[7:]
            elif l.startswith("author-time "):
                author_time = l[12:]
            elif l.startswith("summary "):
                summary = l[8:]

        return {
            "commit": commit_hash,
            "author": author,
            "timestamp": author_time,
            "summary": summary,
            "line": line,
            "file": file_path,
        }

    def find_tests(self, target_file: Optional[str] = None) -> List[str]:
        all_py_files = self.list_files(extensions=[".py", ".ts", ".js"])
        tests = [f for f in all_py_files if "test" in f.lower()]

        if not target_file:
            return tests

        # Score matching tests
        stem = Path(target_file).stem.lower().replace("test_", "").replace("_test", "")
        matches = []
        for t in tests:
            t_lower = t.lower()
            if stem in t_lower:
                matches.append(t)
        return matches or tests

    def get_repository_metadata(self) -> Dict[str, Any]:
        head = self._run_git(["rev-parse", "HEAD"]) or "0000000000000000"
        branch = self._run_git(["rev-parse", "--abbrev-ref", "HEAD"]) or "main"
        remote = self._run_git(["config", "--get", "remote.origin.url"]) or f"local://{self._root.name}"
        return {
            "root_path": str(self._root),
            "name": self._root.name,
            "head_commit": head,
            "branch": branch,
            "remote_url": remote,
            "is_git_repo": (self._root / ".git").exists(),
        }
