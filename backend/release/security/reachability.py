"""
Reachability Intelligence Engine (Brick 4.7)

Implements provider-neutral reachability reasoning:
External Entry Point
        ↓
Application Route
        ↓
Code Path
        ↓
Vulnerable Function / Symbol
        ↓
Affected Dependency

Classifications:
- CONFIRMED_REACHABLE: Complete verified path from entry point to vulnerable symbol
- POTENTIALLY_REACHABLE: Vulnerable symbol/module imported, but path from entry point is unconfirmed
- UNREACHABLE: Package present but vulnerable symbol is not imported, called, or dead code
- REACHABILITY_UNKNOWN: Insufficient call-graph or AST evidence

CRITICAL INVARIANT:
- Never infer confirmed reachability from lexical package-name overlap alone.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Set

from backend.release.security.models import (
    ReachabilityAssessment,
    ReachabilityStatus,
    SecurityFinding,
)


class ReachabilityIntelligenceEngine:
    """
    Controller-authoritative reachability intelligence analyzer.
    Evaluates call graphs, route mappings, AST traces, and symbol references
    to determine true runtime exploitability reachability.
    """

    def __init__(self):
        pass

    def evaluate_reachability(
        self,
        finding: SecurityFinding,
        call_graph: Optional[Dict[str, List[str]]] = None,
        registered_routes: Optional[List[str]] = None,
        imported_symbols: Optional[Dict[str, Set[str]]] = None,
        evidence_snippets: Optional[List[str]] = None,
    ) -> ReachabilityAssessment:
        """
        Evaluate reachability from external routes through code paths to the vulnerable function.
        """
        package_name = (finding.package or "").strip().lower()
        vulnerable_symbol = self._extract_vulnerable_symbol(finding)

        # 1. Reject lexical overlap masquerading as reachability
        if evidence_snippets:
            is_lexical, lexical_reason = self._detect_lexical_only_overlap(
                package_name, vulnerable_symbol, evidence_snippets
            )
            if is_lexical:
                return ReachabilityAssessment(
                    target_package=finding.package or "unknown",
                    vulnerable_symbol=vulnerable_symbol,
                    status=ReachabilityStatus.REACHABILITY_UNKNOWN,
                    entry_point=None,
                    route=None,
                    code_path=[],
                    rationale=f"Lexical overlap rejected: {lexical_reason}. No structural call-graph or execution path found.",
                    confidence=0.9,
                    is_lexical_only=True,
                )

        # 2. Check if static/AST imports even reference the package or vulnerable symbol
        if imported_symbols is not None:
            pkg_imports = imported_symbols.get(package_name)
            if pkg_imports is None:
                # Package is never imported in the codebase
                return ReachabilityAssessment(
                    target_package=finding.package or "unknown",
                    vulnerable_symbol=vulnerable_symbol,
                    status=ReachabilityStatus.UNREACHABLE,
                    entry_point=None,
                    route=None,
                    code_path=[],
                    rationale=f"Package '{package_name}' is declared as a dependency but is never imported in application source.",
                    confidence=0.95,
                    is_lexical_only=False,
                )

            if vulnerable_symbol and vulnerable_symbol not in pkg_imports and "*" not in pkg_imports:
                # Package is imported, but the vulnerable function/symbol is NEVER imported or used
                return ReachabilityAssessment(
                    target_package=finding.package or "unknown",
                    vulnerable_symbol=vulnerable_symbol,
                    status=ReachabilityStatus.UNREACHABLE,
                    entry_point=None,
                    route=None,
                    code_path=[],
                    rationale=f"Package '{package_name}' is imported, but vulnerable symbol '{vulnerable_symbol}' is never imported or referenced.",
                    confidence=0.92,
                    is_lexical_only=False,
                )

        # 3. Call-Graph & Route Trace Analysis
        if call_graph and registered_routes:
            trace = self._find_route_to_symbol_trace(
                routes=registered_routes,
                call_graph=call_graph,
                package_name=package_name,
                vulnerable_symbol=vulnerable_symbol,
            )
            if trace:
                entry_point, route, path = trace
                return ReachabilityAssessment(
                    target_package=finding.package or "unknown",
                    vulnerable_symbol=vulnerable_symbol,
                    status=ReachabilityStatus.CONFIRMED_REACHABLE,
                    entry_point=entry_point,
                    route=route,
                    code_path=path,
                    rationale=f"Confirmed execution path from route '{route}' to vulnerable symbol '{vulnerable_symbol or package_name}' via {len(path)} hops.",
                    confidence=0.98,
                    is_lexical_only=False,
                )

            # If call graph exists but no route connects to symbol:
            # Check if symbol is called in some internal path
            internal_call = self._is_symbol_called_in_graph(call_graph, package_name, vulnerable_symbol)
            if internal_call:
                return ReachabilityAssessment(
                    target_package=finding.package or "unknown",
                    vulnerable_symbol=vulnerable_symbol,
                    status=ReachabilityStatus.POTENTIALLY_REACHABLE,
                    entry_point=None,
                    route=None,
                    code_path=internal_call,
                    rationale=f"Vulnerable symbol '{vulnerable_symbol or package_name}' is invoked in internal code, but no direct public route was verified.",
                    confidence=0.75,
                    is_lexical_only=False,
                )
            else:
                return ReachabilityAssessment(
                    target_package=finding.package or "unknown",
                    vulnerable_symbol=vulnerable_symbol,
                    status=ReachabilityStatus.UNREACHABLE,
                    entry_point=None,
                    route=None,
                    code_path=[],
                    rationale=f"Call-graph confirms vulnerable symbol '{vulnerable_symbol or package_name}' is not reachable from any code path.",
                    confidence=0.90,
                    is_lexical_only=False,
                )

        # 4. Fallback if finding specifically provided reachability flag with evidence
        if finding.is_reachable and finding.evidence_ids:
            return ReachabilityAssessment(
                target_package=finding.package or "unknown",
                vulnerable_symbol=vulnerable_symbol,
                status=ReachabilityStatus.POTENTIALLY_REACHABLE,
                rationale="Scanner reported reachability flag, pending full call-graph verification.",
                evidence_ids=finding.evidence_ids,
                confidence=0.70,
                is_lexical_only=False,
            )

        # 5. Default: Unknown
        return ReachabilityAssessment(
            target_package=finding.package or "unknown",
            vulnerable_symbol=vulnerable_symbol,
            status=ReachabilityStatus.REACHABILITY_UNKNOWN,
            rationale="Insufficient static call-graph or execution flow evidence to confirm or refute reachability.",
            confidence=0.50,
            is_lexical_only=False,
        )

    def _extract_vulnerable_symbol(self, finding: SecurityFinding) -> Optional[str]:
        """Extract vulnerable function or class from finding metadata, raw payload, description, or guidance."""
        if hasattr(finding, "vulnerable_functions") and finding.vulnerable_functions:
            return str(finding.vulnerable_functions[0])
        if finding.raw_payload and isinstance(finding.raw_payload, dict):
            v_funcs = finding.raw_payload.get("vulnerable_functions") or finding.raw_payload.get("vulnerable_symbols")
            if v_funcs and isinstance(v_funcs, list) and len(v_funcs) > 0:
                return str(v_funcs[0])
            if finding.raw_payload.get("vulnerable_function"):
                return str(finding.raw_payload.get("vulnerable_function"))
            if finding.raw_payload.get("symbol"):
                return str(finding.raw_payload.get("symbol"))

        text = f"{finding.description} {finding.remediation_guidance} {finding.cve or ''}"

        # Match patterns like: function 'parse_xml', method `loads`, symbol 'eval'
        m = re.search(r"(?:function|method|symbol|call to|in)\s+['`\"]?([a-zA-Z0-9_]+(?:\.[a-zA-Z0-9_]+)?)['`\"]?", text, re.IGNORECASE)
        if m:
            sym = m.group(1).split(".")[-1]
            if len(sym) > 2 and sym.lower() not in ("the", "this", "file", "line", "code", "package"):
                return sym

        return None

    def _detect_lexical_only_overlap(
        self,
        package_name: str,
        vulnerable_symbol: Optional[str],
        snippets: List[str],
    ) -> Tuple[bool, str]:
        """
        Detect if snippet only has lexical substring matches in comments, docstrings, or unrelated strings.
        """
        if not package_name:
            return False, ""

        has_comment_match = False
        has_code_invocation = False

        for snippet in snippets:
            for line in snippet.splitlines():
                stripped = line.strip()
                if not stripped:
                    continue

                # Comments or docstrings
                if stripped.startswith(("#", "//", "/*", "*", '"""', "'''")):
                    if package_name in stripped.lower():
                        has_comment_match = True
                    continue

                # Check if it's actual import or call
                import_pattern = rf"\b(?:import\s+{package_name}|from\s+{package_name}\b)"
                call_pattern = rf"\b{package_name}\.[a-zA-Z0-9_]+"
                if re.search(import_pattern, stripped, re.IGNORECASE) or re.search(call_pattern, stripped, re.IGNORECASE):
                    has_code_invocation = True
                    break

                if vulnerable_symbol and re.search(rf"\b{vulnerable_symbol}\s*\(", stripped):
                    has_code_invocation = True
                    break

        if has_comment_match and not has_code_invocation:
            return True, f"Keyword '{package_name}' only appears in comments or documentation"

        return False, ""

    def _find_route_to_symbol_trace(
        self,
        routes: List[str],
        call_graph: Dict[str, List[str]],
        package_name: str,
        vulnerable_symbol: Optional[str],
    ) -> Optional[Tuple[str, str, List[str]]]:
        """
        Search for a path in the call graph starting from any registered route handler
        to the target package / vulnerable symbol.
        """
        target_token = vulnerable_symbol.lower() if vulnerable_symbol else package_name.lower()

        for route in routes:
            # Route format e.g. "POST /api/v1/checkout -> app.handlers:handle_checkout"
            entry_parts = route.split("->")
            entry_point = entry_parts[0].strip()
            handler = entry_parts[1].strip() if len(entry_parts) > 1 else entry_point

            # BFS from handler
            queue = [[handler]]
            visited = {handler}

            while queue:
                path = queue.pop(0)
                curr = path[-1]

                # Check if current node invokes the target symbol or package
                if vulnerable_symbol:
                    if vulnerable_symbol.lower() in curr.lower():
                        return entry_point, route, path
                elif package_name and package_name.lower() in curr.lower():
                    return entry_point, route, path

                for neighbor in call_graph.get(curr, []):
                    if neighbor not in visited:
                        visited.add(neighbor)
                        queue.append(path + [neighbor])

        return None

    def _is_symbol_called_in_graph(
        self,
        call_graph: Dict[str, List[str]],
        package_name: str,
        vulnerable_symbol: Optional[str],
    ) -> Optional[List[str]]:
        """Check if any node in call graph connects to the target symbol."""
        for src, dests in call_graph.items():
            for d in dests:
                if vulnerable_symbol:
                    if vulnerable_symbol.lower() in d.lower():
                        return [src, d]
                elif package_name and package_name.lower() in d.lower():
                    return [src, d]
        return None
