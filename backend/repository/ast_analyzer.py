"""
Python AST Analysis Engine (ORACLE 5.0 - Step 6)

Performs deterministic static AST analysis on localized source code using
Python's standard library `ast` module.
Extracts:
- Containing class, function, and block scope
- Target line AST expression (subscript, call, attribute, assignment)
- Intra-file callers and callees
- Candidate producer expressions and variables
- Explicit representation of static uncertainty
"""

from __future__ import annotations

import ast
import logging
from typing import Any, Dict, List, Optional, Set
from pydantic import BaseModel, Field

logger = logging.getLogger("oracle.repository.ast_analyzer")


class AstNodeRef(BaseModel):
    """Reference to an AST syntactic construct."""
    node_type: str
    name: str
    line_start: int
    line_end: int
    details: Dict[str, Any] = Field(default_factory=dict)


class AstCallRef(BaseModel):
    """Function/method invocation identified in AST."""
    caller_function: Optional[str] = None
    callee_name: str
    line: int
    is_method_call: bool = False
    receiver: Optional[str] = None
    arguments: List[str] = Field(default_factory=list)
    confidence: str = "HIGH"
    is_dynamically_dispatched: bool = False


class AstAnalysisResult(BaseModel):
    """Structured deliverable of AST inspection for a localized code window."""
    file_path: str
    target_line: int
    containing_class: Optional[str] = None
    containing_function: Optional[str] = None
    function_line_range: Optional[tuple[int, int]] = None
    target_expression_type: Optional[str] = None
    target_expression_repr: Optional[str] = None
    candidate_producers: List[str] = Field(default_factory=list)
    callees_in_function: List[AstCallRef] = Field(default_factory=list)
    calls_on_target_line: List[AstCallRef] = Field(default_factory=list)
    imports: List[str] = Field(default_factory=list)
    has_exception_handling: bool = False
    has_null_check: bool = False
    uncertainty_notes: List[str] = Field(default_factory=list)


class PythonAstAnalyzer:
    """
    Analyzes Python source files to extract semantic structure around a target line.
    """

    def __init__(self, source_code: str, file_path: str = ""):
        self.source_code = source_code
        self.file_path = file_path
        self._tree: Optional[ast.AST] = None
        self._parse_error: Optional[str] = None
        try:
            self._tree = ast.parse(source_code, filename=file_path or "<string>")
        except SyntaxError as e:
            self._parse_error = f"Syntax error at line {e.lineno}: {e.msg}"
            logger.warning(f"Failed to parse AST for {file_path}: {e}")

    @property
    def is_valid_ast(self) -> bool:
        return self._tree is not None

    def analyze(self, target_line: int) -> AstAnalysisResult:
        if not self._tree:
            return AstAnalysisResult(
                file_path=self.file_path,
                target_line=target_line,
                uncertainty_notes=[f"AST unavailable: {self._parse_error}"],
            )

        # 1. Locate containing class and function
        containing_class, containing_func, func_range = self._find_containing_scope(target_line)

        # 2. Extract imports
        imports = self._extract_imports()

        # 3. Find target line expressions (calls, subscripts, assignments)
        target_expr_type, target_expr_repr = self._analyze_target_line_expression(target_line)

        # 4. Extract callees within the containing function
        callees = self._extract_callees(containing_func)

        # 5. Extract calls directly on the target line
        line_calls = [c for c in callees if c.line == target_line]

        # 6. Detect null checks and exception handling in the function
        has_try, has_none_check = self._check_defensive_guards(containing_func, target_line)

        # 7. Identify candidate producers for variables on the target line
        producers = self._find_candidate_producers(containing_func, target_line)

        # 8. Note uncertainties
        uncertainties = []
        for c in line_calls:
            if c.is_dynamically_dispatched:
                uncertainties.append(f"Dynamic receiver '{c.receiver}' requires runtime binding.")

        return AstAnalysisResult(
            file_path=self.file_path,
            target_line=target_line,
            containing_class=containing_class,
            containing_function=containing_func,
            function_line_range=func_range,
            target_expression_type=target_expr_type,
            target_expression_repr=target_expr_repr,
            candidate_producers=producers,
            callees_in_function=callees,
            calls_on_target_line=line_calls,
            imports=imports,
            has_exception_handling=has_try,
            has_null_check=has_none_check,
            uncertainty_notes=uncertainties,
        )

    def _find_containing_scope(
        self, target_line: int
    ) -> tuple[Optional[str], Optional[str], Optional[tuple[int, int]]]:
        if not self._tree:
            return None, None, None

        current_class: Optional[str] = None
        current_func: Optional[str] = None
        func_range: Optional[tuple[int, int]] = None

        for node in ast.walk(self._tree):
            if isinstance(node, ast.ClassDef):
                start = getattr(node, "lineno", 0)
                end = getattr(node, "end_lineno", start + 50)
                if start <= target_line <= end:
                    current_class = node.name

            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                start = getattr(node, "lineno", 0)
                end = getattr(node, "end_lineno", start + 20)
                if start <= target_line <= end:
                    current_func = node.name
                    func_range = (start, end)

        return current_class, current_func, func_range

    def _extract_imports(self) -> List[str]:
        imports = []
        if not self._tree:
            return imports

        for node in ast.walk(self._tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imports.append(alias.name)
            elif isinstance(node, ast.ImportFrom):
                mod = node.module or ""
                for alias in node.names:
                    imports.append(f"{mod}.{alias.name}" if mod else alias.name)
        return imports

    def _analyze_target_line_expression(self, target_line: int) -> tuple[Optional[str], Optional[str]]:
        if not self._tree:
            return None, None

        expr_type: Optional[str] = None
        expr_repr: Optional[str] = None

        for node in ast.walk(self._tree):
            if getattr(node, "lineno", None) == target_line:
                if isinstance(node, ast.Subscript):
                    expr_type = "SUBSCRIPT_ACCESS"
                    expr_repr = ast.unparse(node) if hasattr(ast, "unparse") else "subscript[...]"
                elif isinstance(node, ast.Call) and not expr_type:
                    expr_type = "FUNCTION_CALL"
                    expr_repr = ast.unparse(node) if hasattr(ast, "unparse") else "call(...)"
                elif isinstance(node, ast.Attribute) and not expr_type:
                    expr_type = "ATTRIBUTE_ACCESS"
                    expr_repr = ast.unparse(node) if hasattr(ast, "unparse") else f".{node.attr}"
                elif isinstance(node, ast.Assign) and not expr_type:
                    expr_type = "ASSIGNMENT"
                    expr_repr = ast.unparse(node) if hasattr(ast, "unparse") else "var = ..."

        return expr_type, expr_repr

    def _extract_callees(self, func_name: Optional[str]) -> List[AstCallRef]:
        callees: List[AstCallRef] = []
        if not self._tree:
            return callees

        for node in ast.walk(self._tree):
            if isinstance(node, ast.Call):
                lineno = getattr(node, "lineno", 0)
                callee_name = "unknown"
                is_method = False
                receiver = None
                is_dynamic = False

                if isinstance(node.func, ast.Name):
                    callee_name = node.func.id
                elif isinstance(node.func, ast.Attribute):
                    callee_name = node.func.attr
                    is_method = True
                    if isinstance(node.func.value, ast.Name):
                        receiver = node.func.value.id
                    elif isinstance(node.func.value, ast.Attribute):
                        receiver = getattr(node.func.value, "attr", "nested")
                        is_dynamic = True
                    else:
                        receiver = "expr"
                        is_dynamic = True

                args_repr = []
                for a in node.args:
                    if hasattr(ast, "unparse"):
                        args_repr.append(ast.unparse(a))
                    elif isinstance(a, ast.Name):
                        args_repr.append(a.id)

                callees.append(
                    AstCallRef(
                        caller_function=func_name,
                        callee_name=callee_name,
                        line=lineno,
                        is_method_call=is_method,
                        receiver=receiver,
                        arguments=args_repr,
                        is_dynamically_dispatched=is_dynamic,
                    )
                )

        return callees

    def _check_defensive_guards(self, func_name: Optional[str], target_line: int) -> tuple[bool, bool]:
        has_try = False
        has_none_check = False
        if not self._tree:
            return False, False

        for node in ast.walk(self._tree):
            if isinstance(node, ast.Try):
                start = getattr(node, "lineno", 0)
                end = getattr(node, "end_lineno", start + 30)
                if start <= target_line <= end:
                    has_try = True

            elif isinstance(node, ast.If):
                start = getattr(node, "lineno", 0)
                end = getattr(node, "end_lineno", start + 10)
                if start <= target_line <= end:
                    # Check if test involves 'is None' or 'is not None'
                    test_str = ast.unparse(node.test).lower() if hasattr(ast, "unparse") else ""
                    if "none" in test_str:
                        has_none_check = True

        return has_try, has_none_check

    def _find_candidate_producers(self, func_name: Optional[str], target_line: int) -> List[str]:
        producers = []
        if not self._tree:
            return producers

        for node in ast.walk(self._tree):
            if isinstance(node, ast.Assign):
                line = getattr(node, "lineno", 0)
                if line < target_line:
                    # Target assignment before target line is a potential producer
                    target_names = []
                    for t in node.targets:
                        if isinstance(t, ast.Name):
                            target_names.append(t.id)

                    val_str = ast.unparse(node.value) if hasattr(ast, "unparse") else "expr"
                    for tname in target_names:
                        producers.append(f"{tname} = {val_str} (line {line})")

        return producers[-3:]  # Return closest 3 assignments
