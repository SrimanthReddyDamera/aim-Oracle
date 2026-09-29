"""
ORACLE 5.1 — Sandbox Patch Application & Metrics

Applies actual Git unified diff patches inside isolated sandbox repositories:
- Calculates cryptographic patch SHA-256 digest.
- Measures files modified, insertions (+), and deletions (-).
- Uses git apply with pure-Python unified diff fallback.
- Explicitly handles patch failure with non-zero exit codes.
"""

from __future__ import annotations

import hashlib
import re
import subprocess
from pathlib import Path
from typing import List, NamedTuple, Optional, Tuple


class PatchApplicationError(Exception):
    """Raised when a patch cannot be cleanly applied to target repository."""
    pass


class PatchResult(NamedTuple):
    success: bool
    patch_sha256: str
    files_modified: List[str]
    insertions: int
    deletions: int
    error_message: Optional[str] = None


class PatchStats(NamedTuple):
    patch_sha256: str
    target_files: List[str]
    insertions: int
    deletions: int


class PatchApplier:
    """Applies unified diff patches to sandbox repositories and calculates diff metrics."""

    def __init__(self, patch_text: Optional[str] = None):
        self.patch_text = (patch_text or "").strip()
        self.patch_sha256 = (
            hashlib.sha256(self.patch_text.encode("utf-8")).hexdigest()
            if self.patch_text
            else ""
        )

    def inspect_patch(self, text: Optional[str] = None) -> PatchStats:
        """Parses the patch to discover modified files, insertions, and deletions."""
        p_text = text if text is not None else self.patch_text
        target_files: List[str] = []
        insertions = 0
        deletions = 0

        for line in p_text.splitlines():
            # Check for file markers
            if line.startswith("+++ b/"):
                file_path = line[6:].strip()
                if file_path not in target_files and file_path != "/dev/null":
                    target_files.append(file_path)
            elif line.startswith("+++ ") and not line.startswith("+++ b/"):
                file_path = line[4:].strip()
                if file_path.startswith("b/"):
                    file_path = file_path[2:]
                if file_path not in target_files and file_path != "/dev/null":
                    target_files.append(file_path)
            elif line.startswith("+") and not line.startswith("+++"):
                insertions += 1
            elif line.startswith("-") and not line.startswith("---"):
                deletions += 1

        sha256 = hashlib.sha256(p_text.encode("utf-8")).hexdigest()
        return PatchStats(
            patch_sha256=sha256,
            target_files=target_files,
            insertions=insertions,
            deletions=deletions,
        )

    def apply(self, patch_text: str, repo_dir: Path) -> PatchResult:
        """Applies a patch given text and directory, returning a PatchResult."""
        self.patch_text = patch_text.strip()
        self.patch_sha256 = hashlib.sha256(self.patch_text.encode("utf-8")).hexdigest()
        stats = self.inspect_patch(self.patch_text)

        try:
            self.apply_patch(repo_dir)
            return PatchResult(
                success=True,
                patch_sha256=stats.patch_sha256,
                files_modified=stats.target_files,
                insertions=stats.insertions,
                deletions=stats.deletions,
                error_message=None,
            )
        except Exception as exc:
            return PatchResult(
                success=False,
                patch_sha256=stats.patch_sha256,
                files_modified=stats.target_files,
                insertions=stats.insertions,
                deletions=stats.deletions,
                error_message=str(exc),
            )

    def apply_patch(self, repo_dir: Path) -> PatchStats:
        """
        Applies patch to repo_dir.
        Attempts git apply first; falls back to pure-Python hunk applier.
        Raises PatchApplicationError on failure.
        """
        stats = self.inspect_patch()

        # Method 1: Git apply if .git is available
        git_dir = repo_dir / ".git"
        if git_dir.exists():
            try:
                res = subprocess.run(
                    ["git", "apply", "--whitespace=nowarn", "-"],
                    input=self.patch_text,
                    cwd=str(repo_dir),
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                if res.returncode == 0:
                    return stats
            except Exception:
                pass

        # Method 2: Pure-Python unified diff applier fallback
        success = self._apply_pure_python(repo_dir)
        if not success:
            raise PatchApplicationError(
                f"Failed to apply patch ({self.patch_sha256[:12]}). Hunks did not match working tree."
            )

        return stats

    def _apply_pure_python(self, repo_dir: Path) -> bool:
        """Fallback unified diff applier for environments without git binary or detached trees."""
        file_diffs = self._split_diff_by_file()
        if not file_diffs:
            return False

        for target_file, diff_lines in file_diffs:
            file_path = repo_dir / target_file

            # Check if creating a new file
            is_new_file = any("--- /dev/null" in line or "new file mode" in line for line in diff_lines)

            if is_new_file or not file_path.exists():
                file_path.parent.mkdir(parents=True, exist_ok=True)
                # Collect all added lines
                new_content_lines = []
                for line in diff_lines:
                    if line.startswith("+") and not line.startswith("+++"):
                        new_content_lines.append(line[1:])
                file_path.write_text("\n".join(new_content_lines) + "\n", encoding="utf-8")
                continue

            try:
                original_content = file_path.read_text(encoding="utf-8", errors="replace")
                patched_content = self._apply_file_hunks(original_content, diff_lines)
                if patched_content is None:
                    return False
                file_path.write_text(patched_content, encoding="utf-8")
            except Exception:
                return False

        return True

    def _split_diff_by_file(self) -> List[Tuple[str, List[str]]]:
        """Splits multi-file unified diff into per-file chunks."""
        results: List[Tuple[str, List[str]]] = []
        current_file: str | None = None
        current_lines: List[str] = []

        for line in self.patch_text.splitlines():
            if line.startswith("diff --git"):
                if current_file and current_lines:
                    results.append((current_file, current_lines))
                    current_lines = []
                current_file = None
            elif line.startswith("+++ b/"):
                current_file = line[6:].strip()
            elif line.startswith("+++ ") and not line.startswith("+++ b/"):
                f = line[4:].strip()
                current_file = f[2:] if f.startswith("b/") else f
            
            if current_file:
                current_lines.append(line)

        if current_file and current_lines:
            results.append((current_file, current_lines))

        return results

    def _apply_file_hunks(self, content: str, hunk_lines: List[str]) -> str | None:
        """Applies hunks to content line by line."""
        lines = content.splitlines()

        hunk_header_re = re.compile(r"^@@\s+-(\d+)(?:,(\d+))?\s+\+(\d+)(?:,(\d+))?\s+@@")

        idx = 0
        while idx < len(hunk_lines):
            line = hunk_lines[idx]
            match = hunk_header_re.match(line)
            if not match:
                idx += 1
                continue

            old_start = int(match.group(1)) - 1  # 0-indexed
            idx += 1

            old_block: List[str] = []
            new_block: List[str] = []

            while idx < len(hunk_lines) and not hunk_header_re.match(hunk_lines[idx]):
                hline = hunk_lines[idx]
                if hline.startswith("-"):
                    old_block.append(hline[1:])
                elif hline.startswith("+"):
                    new_block.append(hline[1:])
                elif hline.startswith(" "):
                    old_block.append(hline[1:])
                    new_block.append(hline[1:])
                idx += 1

            # Match and replace old_block in lines around old_start
            match_found = False
            for offset in range(-5, 6):
                pos = old_start + offset
                if pos >= 0 and pos + len(old_block) <= len(lines):
                    if lines[pos : pos + len(old_block)] == old_block:
                        lines[pos : pos + len(old_block)] = new_block
                        match_found = True
                        break

            if not match_found:
                # Direct string replacement fallback
                old_text = "\n".join(old_block)
                new_text = "\n".join(new_block)
                current_joined = "\n".join(lines)
                if old_text in current_joined:
                    current_joined = current_joined.replace(old_text, new_text, 1)
                    lines = current_joined.splitlines()
                else:
                    return None

        return "\n".join(lines) + ("\n" if content.endswith("\n") else "")
