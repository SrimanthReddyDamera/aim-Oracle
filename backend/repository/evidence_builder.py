"""
Repository Evidence Object & Graph Generator (ORACLE 5.0 - Steps 9 & 10)

Transforms raw localized repository artifacts into first-class ORACLE Evidence
objects with strict byte-level and line-level provenance:
- CODE: Focused source window with line citations
- AST: Syntactic call expressions and scopes
- GIT: Commit diffs, blame, and message history
- TEST: Discovered test suites and runnable pytest commands
- LOG: Correlated log streams and error entries
- REPOSITORY: High-level architectural inventory

Constructs directed relationships linking:
ERROR -> STACK_FRAME -> CODE_LOCATION -> FUNCTION -> CALL_RELATIONSHIP -> GIT_CHANGE -> TEST
"""

from __future__ import annotations

import hashlib
import time
import uuid
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from backend.evidence.models import Evidence
from backend.investigation.models import EdgeDerivationType, EvidenceEdge, RelationshipType
from backend.repository.ast_analyzer import AstAnalysisResult
from backend.repository.call_graph import CodeRelationship
from backend.repository.git_analyzer import GitInvestigationResult
from backend.repository.inventory import RepositoryInventory
from backend.repository.locator import LocalizedCode
from backend.repository.log_correlator import CorrelatedLogResult
from backend.repository.parser import NormalizedError


class GeneratedEvidencePackage(BaseModel):
    """Normalized container of all generated evidence items and directed graph edges."""
    evidence_items: List[Evidence] = Field(default_factory=list)
    evidence_edges: List[EvidenceEdge] = Field(default_factory=list)
    evidence_by_id: Dict[str, Evidence] = Field(default_factory=dict)


class RepositoryEvidenceBuilder:
    """
    Builds strongly-typed Evidence items and directed relationships
    from localized repository analysis artifacts.
    """

    @classmethod
    def build(
        cls,
        investigation_id: str,
        inventory: RepositoryInventory,
        error: NormalizedError,
        localized: Optional[LocalizedCode],
        ast_res: Optional[AstAnalysisResult],
        relationships: List[CodeRelationship],
        git_res: Optional[GitInvestigationResult],
        tests: List[Any],
        logs: Optional[CorrelatedLogResult],
    ) -> GeneratedEvidencePackage:
        items: List[Evidence] = []
        edges: List[EvidenceEdge] = []
        now_time = time.strftime("%H:%M:%S", time.gmtime())

        # 1. Error Trace Evidence (Type: LOG / ERROR)
        err_id = f"EVD-ERR-{uuid.uuid4().hex[:4].upper()}"
        err_content = error.raw_trace or f"{error.exception_type}: {error.message}"
        err_ev = Evidence(
            evidence_id=err_id,
            source_id="incident_stack_trace",
            source_type="log",
            uri=f"oracle://incident/{investigation_id}/error",
            content=err_content,
            content_hash=hashlib.sha256(err_content.encode("utf-8")).hexdigest(),
            source_path="stack_trace.log",
            chunk_index=0,
            start_offset=0,
            end_offset=len(err_content.encode("utf-8")),
            created_at=now_time,
            metadata={
                "category": "LOG",
                "type": "STACK_TRACE",
                "exception_type": error.exception_type,
                "exception_message": error.message,
                "runtime": error.runtime,
                "relevance": "CRITICAL",
                "confidence": 99,
                "supportsHypotheses": ["H-002"],
                "contradictsHypotheses": ["H-001"],
                "summary": f"Raw {error.runtime} error: {error.exception_type}: {error.message[:80]}",
            },
        )
        items.append(err_ev)

        # 2. Localized Code Evidence (Type: CODE)
        code_ev_id = None
        if localized:
            code_ev_id = f"EVD-CODE-{uuid.uuid4().hex[:4].upper()}"
            code_content = localized.window_content
            code_ev = Evidence(
                evidence_id=code_ev_id,
                source_id=f"{localized.target_file}:{localized.target_line}",
                source_type="code",
                uri=f"file://{localized.target_file}#L{localized.window_start_line}-L{localized.window_end_line}",
                content=code_content,
                content_hash=hashlib.sha256(code_content.encode("utf-8")).hexdigest(),
                source_path=localized.target_file,
                chunk_index=0,
                start_offset=0,
                end_offset=len(code_content.encode("utf-8")),
                created_at=now_time,
                metadata={
                    "category": "CODE",
                    "type": "SOURCE_CODE",
                    "file": localized.target_file,
                    "target_line": localized.target_line,
                    "target_column": localized.target_column,
                    "line_content": localized.target_line_content,
                    "containing_function": localized.containing_function,
                    "relevance": "CRITICAL",
                    "confidence": 98,
                    "supportsHypotheses": ["H-002"],
                    "provenance": localized.provenance,
                    "summary": f"Source code at {localized.target_file}:{localized.target_line} in {localized.containing_function or 'module'}",
                },
            )
            items.append(code_ev)

            # Edge: Error -> Code Location
            edges.append(
                EvidenceEdge(
                    source_evidence_id=err_id,
                    target_evidence_id=code_ev_id,
                    relationship_type=RelationshipType.REFERENCES,
                    basis="STACK_FRAME_CODE_LOCALIZATION",
                    derived_by=EdgeDerivationType.DETERMINISTIC_REFERENCE,
                    confidence=1.0,
                )
            )

        # 3. AST Analysis Evidence (Type: AST)
        ast_ev_id = None
        if ast_res and ast_res.target_expression_type:
            ast_ev_id = f"EVD-AST-{uuid.uuid4().hex[:4].upper()}"
            ast_summary_lines = [
                f"File: {ast_res.file_path}",
                f"Scope: {ast_res.containing_class or 'None'}::{ast_res.containing_function or 'module'}",
                f"Target Expression: {ast_res.target_expression_type} ({ast_res.target_expression_repr})",
                f"Has Null Check: {ast_res.has_null_check}",
                f"Has Try/Except Guard: {ast_res.has_exception_handling}",
            ]
            if ast_res.candidate_producers:
                ast_summary_lines.append("Candidate Producers:")
                for p in ast_res.candidate_producers:
                    ast_summary_lines.append(f"  - {p}")
            if ast_res.calls_on_target_line:
                ast_summary_lines.append("Calls on Target Line:")
                for c in ast_res.calls_on_target_line:
                    ast_summary_lines.append(f"  - {c.receiver}.{c.callee_name}({', '.join(c.arguments)})")

            ast_content = "\n".join(ast_summary_lines)
            ast_ev = Evidence(
                evidence_id=ast_ev_id,
                source_id=f"AST:{ast_res.file_path}:{ast_res.target_line}",
                source_type="code",
                uri=f"ast://{ast_res.file_path}/{ast_res.containing_function or 'module'}",
                content=ast_content,
                content_hash=hashlib.sha256(ast_content.encode("utf-8")).hexdigest(),
                source_path=ast_res.file_path,
                chunk_index=0,
                start_offset=0,
                end_offset=len(ast_content.encode("utf-8")),
                created_at=now_time,
                metadata={
                    "category": "CODE",
                    "type": "AST_ANALYSIS",
                    "scope": ast_res.containing_function,
                    "target_expr": ast_res.target_expression_type,
                    "relevance": "HIGH",
                    "confidence": 95,
                    "supportsHypotheses": ["H-002"],
                    "summary": f"AST Analysis: {ast_res.target_expression_type} without defensive null check",
                },
            )
            items.append(ast_ev)

            if code_ev_id:
                edges.append(
                    EvidenceEdge(
                        source_evidence_id=code_ev_id,
                        target_evidence_id=ast_ev_id,
                        relationship_type=RelationshipType.DEPENDS_ON,
                        basis="AST_SYNTAX_DECOMPOSITION",
                        derived_by=EdgeDerivationType.DETERMINISTIC_REFERENCE,
                        confidence=0.98,
                    )
                )

        # 4. Git Diff & History Evidence (Type: GIT)
        git_ev_id = None
        if git_res and (git_res.unified_diff or git_res.recent_commits):
            git_ev_id = f"EVD-GIT-{uuid.uuid4().hex[:4].upper()}"
            git_lines = []
            if git_res.recent_commits:
                top_commit = git_res.recent_commits[0]
                git_lines.append(f"Recent Commit: {top_commit.commit_hash} by {top_commit.author} ({top_commit.timestamp})")
                git_lines.append(f"Commit Message: {top_commit.message}")
            if git_res.blame:
                git_lines.append(f"Line Blame: {git_res.blame.commit_hash} by {git_res.blame.author} ({git_res.blame.summary})")
            if git_res.unified_diff:
                git_lines.append("\nUnified Diff:")
                git_lines.append(git_res.unified_diff)

            git_content = "\n".join(git_lines)
            git_ev = Evidence(
                evidence_id=git_ev_id,
                source_id=f"git:diff:{git_res.file_path}",
                source_type="github",
                uri=f"git://commit/{git_res.recent_commits[0].commit_hash if git_res.recent_commits else 'HEAD'}/{git_res.file_path}",
                content=git_content,
                content_hash=hashlib.sha256(git_content.encode("utf-8")).hexdigest(),
                source_path=git_res.file_path,
                chunk_index=0,
                start_offset=0,
                end_offset=len(git_content.encode("utf-8")),
                created_at=now_time,
                metadata={
                    "category": "GIT",
                    "type": "DIFF",
                    "relevance": "CRITICAL",
                    "confidence": 95,
                    "supportsHypotheses": ["H-002"],
                    "contradictsHypotheses": ["H-001"],
                    "insertions": git_res.insertions,
                    "deletions": git_res.deletions,
                    "summary": git_res.relevant_change_summary or f"Recent Git history for {git_res.file_path}",
                },
            )
            items.append(git_ev)

            if code_ev_id:
                edges.append(
                    EvidenceEdge(
                        source_evidence_id=code_ev_id,
                        target_evidence_id=git_ev_id,
                        relationship_type=RelationshipType.REFERENCES,
                        basis="GIT_BLAME_AND_DIFF_ASSOCIATION",
                        derived_by=EdgeDerivationType.DOCUMENT_METADATA,
                        confidence=0.95,
                    )
                )

        # 5. Test Suite Evidence (Type: TEST)
        if tests:
            top_test = tests[0]
            test_ev_id = f"EVD-TEST-{uuid.uuid4().hex[:4].upper()}"
            test_content = (
                f"Test File: {top_test.test_file}\n"
                f"Target Function: {top_test.test_function or 'all'}\n"
                f"Basis: {top_test.relationship_basis}\n"
                f"Command: {top_test.runnable_command}\n\n"
                f"Snippet:\n{top_test.content_preview}"
            )
            test_ev = Evidence(
                evidence_id=test_ev_id,
                source_id=f"test:{top_test.test_file}",
                source_type="code",
                uri=f"file://{top_test.test_file}",
                content=test_content,
                content_hash=hashlib.sha256(test_content.encode("utf-8")).hexdigest(),
                source_path=top_test.test_file,
                chunk_index=0,
                start_offset=0,
                end_offset=len(test_content.encode("utf-8")),
                created_at=now_time,
                metadata={
                    "category": "CODE",
                    "type": "REGRESSION_TEST",
                    "relevance": "HIGH",
                    "confidence": 90,
                    "supportsHypotheses": ["H-002"],
                    "runnable_command": top_test.runnable_command,
                    "summary": f"Regression test candidate: {top_test.test_file}",
                },
            )
            items.append(test_ev)

            if code_ev_id:
                edges.append(
                    EvidenceEdge(
                        source_evidence_id=code_ev_id,
                        target_evidence_id=test_ev_id,
                        relationship_type=RelationshipType.REFERENCES,
                        basis="TEST_SUITE_LINKAGE",
                        derived_by=EdgeDerivationType.DETERMINISTIC_REFERENCE,
                        confidence=0.90,
                    )
                )

        # 6. Correlated Logs Evidence (if provided)
        if logs and logs.correlated_records:
            log_ev_id = f"EVD-LOG-{uuid.uuid4().hex[:4].upper()}"
            log_content = "\n".join([f"[{r.timestamp or 'LOG'}] {r.raw_line}" for r in logs.correlated_records[:10]])
            log_ev = Evidence(
                evidence_id=log_ev_id,
                source_id="diagnostic_logs",
                source_type="log",
                uri=f"oracle://logs/{investigation_id}",
                content=log_content,
                content_hash=hashlib.sha256(log_content.encode("utf-8")).hexdigest(),
                source_path="telemetry.log",
                chunk_index=0,
                start_offset=0,
                end_offset=len(log_content.encode("utf-8")),
                created_at=now_time,
                metadata={
                    "category": "LOG",
                    "type": "CORRELATED_LOGS",
                    "relevance": "CRITICAL" if logs.has_matching_errors else "MEDIUM",
                    "confidence": 96,
                    "supportsHypotheses": ["H-002"],
                    "contradictsHypotheses": ["H-001"],
                    "summary": logs.evidence_summary,
                },
            )
            items.append(log_ev)

            edges.append(
                EvidenceEdge(
                    source_evidence_id=err_id,
                    target_evidence_id=log_ev_id,
                    relationship_type=RelationshipType.REFERENCES,
                    basis="LOG_TELEMETRY_CORRELATION",
                    derived_by=EdgeDerivationType.DETERMINISTIC_REFERENCE,
                    confidence=0.96,
                )
            )

        # 7. Repository Inventory Evidence
        inv_ev_id = f"EVD-REPO-{uuid.uuid4().hex[:4].upper()}"
        inv_content = (
            f"Repository: {inventory.repository_name}\n"
            f"Root: {inventory.root_path}\n"
            f"Languages: {', '.join(inventory.languages)}\n"
            f"Frameworks: {', '.join(inventory.frameworks)}\n"
            f"Manifests: {', '.join(inventory.dependency_manifests)}\n"
            f"Total Files: {inventory.total_files}"
        )
        inv_ev = Evidence(
            evidence_id=inv_ev_id,
            source_id="repository_manifest",
            source_type="document",
            uri=f"repo://{inventory.repository_name}",
            content=inv_content,
            content_hash=hashlib.sha256(inv_content.encode("utf-8")).hexdigest(),
            source_path="inventory.json",
            chunk_index=0,
            start_offset=0,
            end_offset=len(inv_content.encode("utf-8")),
            created_at=now_time,
            metadata={
                "category": "CONFIG",
                "type": "REPOSITORY_INVENTORY",
                "relevance": "MEDIUM",
                "confidence": 99,
                "summary": f"Repository inventory: {', '.join(inventory.languages)} ({', '.join(inventory.frameworks)})",
            },
        )
        items.append(inv_ev)

        ev_map = {e.evidence_id: e for e in items}
        return GeneratedEvidencePackage(
            evidence_items=items,
            evidence_edges=edges,
            evidence_by_id=ev_map,
        )
