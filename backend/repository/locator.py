"""
Error to Code Localization Engine (ORACLE 5.0 - Step 5)

Deterministic mapping of parsed stack traces to actual repository files,
functions, line numbers, and focused evidence windows.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from backend.repository.adapter import RepositoryAdapter
from backend.repository.parser import NormalizedError, StackFrame

logger = logging.getLogger("oracle.repository.locator")


class LocalizedCode(BaseModel):
    """Deterministic localization of an incident failure to source code."""
    target_file: str
    target_line: int
    target_column: Optional[int] = None
    target_line_content: str = ""
    window_start_line: int = 1
    window_end_line: int = 1
    window_content: str = ""
    containing_function: Optional[str] = None
    containing_class: Optional[str] = None
    frame: Optional[StackFrame] = None
    confidence: str = "HIGH"  # HIGH, MEDIUM, LOW
    provenance: Dict[str, Any] = Field(default_factory=dict)


class CodeLocator:
    """
    Locates stack frames against real files in the repository.
    Handles path resolution (full relative, partial relative, or base filename).
    Constructs focused evidence windows avoiding full repository context dumps.
    """

    DEFAULT_CONTEXT_LINES = 15

    def __init__(self, adapter: RepositoryAdapter):
        self.adapter = adapter
        self._all_files_cache: Optional[List[str]] = None

    def _get_all_files(self) -> List[str]:
        if self._all_files_cache is None:
            self._all_files_cache = self.adapter.list_files(max_files=2000)
        return self._all_files_cache

    def locate(
        self,
        error: NormalizedError,
        context_lines: int = DEFAULT_CONTEXT_LINES,
    ) -> Optional[LocalizedCode]:
        """
        Locates the most relevant (innermost/root) stack frame in the repository.
        If the root frame is not found in the repository, traverses upwards through frames.
        """
        if not error.frames:
            return None

        # Prioritize frames in reverse order (closest to failure)
        candidate_frames = list(reversed(error.frames))

        for frame in candidate_frames:
            resolved_path = self._resolve_file_in_repo(frame.file)
            if resolved_path:
                return self._build_localized_code(resolved_path, frame, context_lines)

        logger.warning(f"Could not locate any stack frames in repository: {[f.file for f in error.frames]}")
        return None

    def locate_all_frames(
        self,
        error: NormalizedError,
        context_lines: int = 5,
    ) -> List[LocalizedCode]:
        """Locates all stack frames that match repository files."""
        results: List[LocalizedCode] = []
        for frame in error.frames:
            resolved_path = self._resolve_file_in_repo(frame.file)
            if resolved_path:
                results.append(self._build_localized_code(resolved_path, frame, context_lines))
        return results

    def _resolve_file_in_repo(self, file_path: str) -> Optional[str]:
        """
        Matches a stack frame file path against actual repository files.
        1. Exact relative path.
        2. Suffix match (e.g. 'payment/payment_service.py' in 'src/payment/payment_service.py').
        3. Filename match if unique.
        """
        clean = file_path.replace("\\", "/").lstrip("/")

        # 1. Exact match
        if self.adapter.file_exists(clean):
            return clean

        all_files = self._get_all_files()

        # 2. Suffix match
        for f in all_files:
            if f.endswith(clean) or clean.endswith(f):
                return f

        # 3. Filename match
        filename = Path(clean).name.lower()
        matches = [f for f in all_files if Path(f).name.lower() == filename]
        if len(matches) == 1:
            return matches[0]
        elif len(matches) > 1:
            # Pick the one with the most path overlap
            matches.sort(key=lambda m: len(set(Path(m).parts).intersection(set(Path(clean).parts))), reverse=True)
            return matches[0]

        return None

    def _build_localized_code(
        self,
        resolved_file: str,
        frame: StackFrame,
        context_lines: int,
    ) -> LocalizedCode:
        target_line = max(1, frame.line)
        start_line = max(1, target_line - context_lines)
        end_line = target_line + context_lines

        lines_slice = self.adapter.read_file_lines(resolved_file, start_line, end_line)
        target_line_content = ""
        for num, content in lines_slice:
            if num == target_line:
                target_line_content = content
                break

        # Format window content with line numbers
        window_lines = []
        for num, content in lines_slice:
            marker = " > " if num == target_line else "   "
            window_lines.append(f"{marker}{num:4d} | {content}")
        window_content = "\n".join(window_lines)

        meta = self.adapter.get_repository_metadata()
        provenance = {
            "repository": meta.get("name", "local"),
            "commit": meta.get("head_commit", "HEAD"),
            "file": resolved_file,
            "target_line": target_line,
            "extraction_method": "STACK_FRAME_CORRELATION",
            "frame_function": frame.function,
        }

        return LocalizedCode(
            target_file=resolved_file,
            target_line=target_line,
            target_column=frame.column,
            target_line_content=target_line_content,
            window_start_line=start_line,
            window_end_line=end_line,
            window_content=window_content,
            containing_function=frame.function,
            frame=frame,
            confidence="HIGH",
            provenance=provenance,
        )
