"""
ORACLE 5.1 — Scope Containment & AST Validation

Compares the patched workspace against the authorized scope boundary
and validates Python AST structures to ensure patches remain strictly
within permissible boundaries without syntax errors or contract violations.
"""

from __future__ import annotations

import ast
import os
from pathlib import Path
from typing import List, Optional, Set

from backend.sandbox.models import ScopeReport
from backend.sandbox.patch import PatchResult


class ScopeValidator:
    """
    Validates that a patch adheres to allowed file boundaries
    and does not introduce AST structural breakage.
    """

    def __init__(self, allowed_files: Optional[List[str]] = None):
        """
        Args:
            allowed_files: List of file paths (relative or normalized) permitted to be modified.
                           If None or empty, all modified files are permitted unless out-of-scope files
                           are explicitly flagged.
        """
        self.allowed_files: List[str] = [self._normalize_path(f) for f in (allowed_files or [])]

    @staticmethod
    def _normalize_path(path_str: str) -> str:
        """Normalizes path separators to forward slashes and strips leading/trailing slashes."""
        p = path_str.replace("\\", "/").strip()
        while p.startswith("./"):
            p = p[2:]
        return p.lstrip("/")

    def validate_scope(
        self,
        workspace_root: Path,
        patch_result: PatchResult,
    ) -> ScopeReport:
        """
        Validates modified files against the allowed boundary and runs AST analysis.
        """
        modified_files = [self._normalize_path(f) for f in patch_result.files_modified]
        unauthorized: List[str] = []

        if self.allowed_files:
            allowed_set = set(self.allowed_files)
            for mod_file in modified_files:
                # Check exact match or if mod_file ends with an allowed relative path
                matched = False
                for allowed in allowed_set:
                    if mod_file == allowed or mod_file.endswith("/" + allowed) or allowed.endswith("/" + mod_file):
                        matched = True
                        break
                if not matched:
                    unauthorized.append(mod_file)

        # AST Validation for Python files in workspace
        ast_valid = True
        ast_violations: List[str] = []

        for mod_file in modified_files:
            target_path = workspace_root / mod_file
            if not target_path.exists():
                # Might be a deleted file or relative mismatch, try searching
                matching = list(workspace_root.glob(f"**/{os.path.basename(mod_file)}"))
                if matching:
                    target_path = matching[0]

            if target_path.exists() and target_path.suffix == ".py":
                try:
                    content = target_path.read_text(encoding="utf-8", errors="replace")
                    parsed_tree = ast.parse(content, filename=str(target_path))
                    # Check for basic sanity: top-level node is Module
                    if not isinstance(parsed_tree, ast.Module):
                        ast_valid = False
                        ast_violations.append(f"{mod_file}: Root AST node is not a Module")
                except SyntaxError as e:
                    ast_valid = False
                    ast_violations.append(f"{mod_file}: SyntaxError at line {e.lineno}: {e.msg}")
                except Exception as e:
                    ast_valid = False
                    ast_violations.append(f"{mod_file}: AST parse failure: {str(e)}")

        is_valid = (len(unauthorized) == 0) and ast_valid

        return ScopeReport(
            is_valid=is_valid,
            allowed_files=self.allowed_files,
            modified_files=modified_files,
            unauthorized_files=unauthorized,
            ast_valid=ast_valid,
            ast_violations=ast_violations,
            files_changed_count=len(modified_files),
            insertions=patch_result.insertions,
            deletions=patch_result.deletions,
        )
