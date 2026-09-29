"""
ORACLE 5.1 — Sandbox Repository Snapshot Manager

Creates deterministic repository snapshots inside isolated sandboxes:
- Clones/copies repository working tree.
- Calculates SHA-256 repository tree digests.
- Resolves HEAD commit and branch state.
- Excludes bytecode, caches, and dangerous host links.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
from pathlib import Path
from typing import NamedTuple, Optional, Set


IGNORE_DIRS: Set[str] = {
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    "venv",
    ".venv",
    "node_modules",
    ".idea",
    ".vscode",
}

IGNORE_EXTS: Set[str] = {
    ".pyc",
    ".pyo",
    ".pyd",
}


class RepositorySnapshot(NamedTuple):
    destination_path: Path
    head_commit: str
    tree_digest: str


class RepositorySnapshotManager:
    """Manages deterministic snapshots of repositories inside isolated sandbox workspaces."""

    def __init__(self, source_repo_path: Path | str):
        self.source_repo_path = Path(source_repo_path).resolve()
        if not self.source_repo_path.exists() or not self.source_repo_path.is_dir():
            raise FileNotFoundError(f"Source repository does not exist: {self.source_repo_path}")

    def create_snapshot(
        self,
        destination_dir: Path,
        target_subdir: Optional[str] = None,
    ) -> RepositorySnapshot:
        """
        Copies the repository into destination_dir and computes:
        - destination path (Path)
        - HEAD commit hash (str)
        - tree digest (SHA-256 hex string)
        """
        dest_repo = (destination_dir / target_subdir) if target_subdir else destination_dir
        dest_repo.mkdir(parents=True, exist_ok=True)

        # Copy repository files while filtering out cache/temporary objects
        for root, dirs, files in os.walk(self.source_repo_path):
            # Modify dirs in-place to skip ignored directories
            dirs[:] = [d for d in dirs if d not in IGNORE_DIRS]

            rel_root = Path(root).relative_to(self.source_repo_path)
            target_root = dest_repo / rel_root
            target_root.mkdir(parents=True, exist_ok=True)

            for file in files:
                if any(file.endswith(ext) for ext in IGNORE_EXTS):
                    continue

                src_file = Path(root) / file
                # Skip symlinks that point outside source_repo_path
                if src_file.is_symlink():
                    try:
                        resolved = src_file.resolve()
                        resolved.relative_to(self.source_repo_path)
                    except (ValueError, RuntimeError):
                        continue

                dst_file = target_root / file
                try:
                    shutil.copy2(src_file, dst_file)
                except Exception:
                    pass

        head_commit = self._get_head_commit()
        tree_digest = self.calculate_tree_digest(dest_repo)

        return RepositorySnapshot(
            destination_path=dest_repo,
            head_commit=head_commit,
            tree_digest=tree_digest,
        )

    def _get_head_commit(self) -> str:
        """Attempts to read Git HEAD commit from source repository."""
        git_dir = self.source_repo_path / ".git"
        if git_dir.exists():
            try:
                res = subprocess.run(
                    ["git", "rev-parse", "HEAD"],
                    cwd=str(self.source_repo_path),
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                if res.returncode == 0 and res.stdout.strip():
                    return res.stdout.strip()
            except Exception:
                pass

        # Fallback digest if git binary is absent
        return hashlib.sha256(str(self.source_repo_path).encode()).hexdigest()[:12]

    @staticmethod
    def calculate_tree_digest(repo_dir: Path) -> str:
        """
        Computes a deterministic SHA-256 digest across all files and relative paths
        in repo_dir.
        """
        hasher = hashlib.sha256()
        file_paths = []

        for root, dirs, files in os.walk(repo_dir):
            dirs.sort()
            for file in sorted(files):
                if file.startswith(".git"):
                    continue
                file_paths.append(Path(root) / file)

        file_paths.sort()

        for p in file_paths:
            rel_path = str(p.relative_to(repo_dir)).replace("\\", "/")
            hasher.update(rel_path.encode("utf-8"))
            try:
                content = p.read_bytes()
                hasher.update(content)
            except Exception:
                pass

        return hasher.hexdigest()
