"""
Call Relationship & Static Graph Engine (ORACLE 5.0 - Step 6b)

Constructs lightweight static call relationship graphs with provenance:
Caller -> Callee -> Dependency.
Enforces the critical boundary: Static relationships are labeled as
'STATIC CALL RELATIONSHIP', never masquerading as dynamic execution traces.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from backend.repository.ast_analyzer import AstAnalysisResult, AstCallRef

logger = logging.getLogger("oracle.repository.call_graph")


class CodeRelationship(BaseModel):
    """Normalized static call relationship with provenance."""
    relationship_id: str
    caller: str
    callee: str
    source_file: str
    line: int
    basis: str = "STATIC CALL RELATIONSHIP"
    confidence: str = "HIGH"
    is_method_call: bool = False
    receiver: Optional[str] = None
    provenance: Dict[str, Any] = Field(default_factory=dict)


class CallGraphBuilder:
    """
    Constructs bounded call graphs around the failure location.
    """

    @classmethod
    def build_from_ast(cls, ast_res: AstAnalysisResult) -> List[CodeRelationship]:
        relationships: List[CodeRelationship] = []
        caller = ast_res.containing_function or "module_scope"

        for idx, call in enumerate(ast_res.callees_in_function):
            rel_id = f"R-{idx+1:03d}"
            target_callee = f"{call.receiver}.{call.callee_name}" if call.receiver else call.callee_name

            rel = CodeRelationship(
                relationship_id=rel_id,
                caller=caller,
                callee=target_callee,
                source_file=ast_res.file_path,
                line=call.line,
                basis="STATIC CALL RELATIONSHIP",
                confidence=call.confidence,
                is_method_call=call.is_method_call,
                receiver=call.receiver,
                provenance={
                    "file": ast_res.file_path,
                    "line": call.line,
                    "arguments": call.arguments,
                    "is_dynamically_dispatched": call.is_dynamically_dispatched,
                    "target_line_correlation": call.line == ast_res.target_line,
                },
            )
            relationships.append(rel)

        return relationships
