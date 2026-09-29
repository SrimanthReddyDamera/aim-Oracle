"""
Git History & Diff Investigation Engine (ORACLE 5.0 - Step 7)

Inspects Git history, commits, blame, and unified diffs around localized code.
Enforces the core rule: Recent commits are evidence, not automatic causal proof.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from backend.repository.adapter import RepositoryAdapter

logger = logging.getLogger("oracle.repository.git_analyzer")


class GitCommitRecord(BaseModel):
    """Normalized Git commit representation."""
    commit_hash: str
    author: str
    email: str = ""
    timestamp: str = ""
    message: str
    is_recent: bool = True


class GitBlameRecord(BaseModel):
    """Line-level blame attribution."""
    file: str
    line: int
    commit_hash: str
    author: str
    timestamp: str = ""
    summary: str = ""


class GitInvestigationResult(BaseModel):
    """Structured deliverable of Git history investigation."""
    file_path: str
    target_line: int
    current_head: str
    recent_commits: List[GitCommitRecord] = Field(default_factory=list)
    blame: Optional[GitBlameRecord] = None
    unified_diff: str = ""
    files_changed: int = 0
    insertions: int = 0
    deletions: int = 0
    relevant_change_summary: Optional[str] = None
    epistemic_warning: str = "Recent Git change is correlational evidence, not standalone causal proof."


class GitHistoryAnalyzer:
    """
    Analyzes repository commit history around localized code.
    """

    def __init__(self, adapter: RepositoryAdapter):
        self.adapter = adapter

    def analyze(self, file_path: str, target_line: int) -> GitInvestigationResult:
        meta = self.adapter.get_repository_metadata()
        head = meta.get("head_commit", "HEAD")

        # 1. Recent commits affecting this file
        raw_commits = self.adapter.get_recent_commits(file_path=file_path, limit=5)
        commits: List[GitCommitRecord] = []
        for c in raw_commits:
            commits.append(
                GitCommitRecord(
                    commit_hash=c.get("hash", "")[:8],
                    author=c.get("author_name", "unknown"),
                    email=c.get("author_email", ""),
                    timestamp=c.get("date", ""),
                    message=c.get("message", ""),
                )
            )

        # 2. Line blame
        blame_record = None
        raw_blame = self.adapter.get_git_blame(file_path=file_path, line=target_line)
        if raw_blame:
            blame_record = GitBlameRecord(
                file=file_path,
                line=target_line,
                commit_hash=raw_blame.get("commit", "")[:8],
                author=raw_blame.get("author", "unknown"),
                timestamp=raw_blame.get("timestamp", ""),
                summary=raw_blame.get("summary", ""),
            )

        # 3. Diff of most recent commit modifying this file
        diff_str = ""
        insertions = 0
        deletions = 0
        change_summary = None

        if commits:
            top_commit = commits[0].commit_hash
            diff_str = self.adapter.get_git_diff(commit_hash=top_commit, file_path=file_path)
            # Count insertions and deletions
            for line in diff_str.split("\n"):
                if line.startswith("+") and not line.startswith("+++"):
                    insertions += 1
                elif line.startswith("-") and not line.startswith("---"):
                    deletions += 1

            if diff_str:
                change_summary = f"Commit {top_commit} ('{commits[0].message}') modified {file_path} (+{insertions}, -{deletions})"

        return GitInvestigationResult(
            file_path=file_path,
            target_line=target_line,
            current_head=head,
            recent_commits=commits,
            blame=blame_record,
            unified_diff=diff_str,
            files_changed=1 if diff_str else 0,
            insertions=insertions,
            deletions=deletions,
            relevant_change_summary=change_summary,
        )
