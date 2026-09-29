"""
Deterministic Test Locator Engine (ORACLE 5.0 - Step 8)

Locates tests related to affected code using deterministic signals:
- File naming conventions (test_*.py, *_test.py)
- Import and symbol reference analysis
- Test function hierarchy
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from backend.repository.adapter import RepositoryAdapter

logger = logging.getLogger("oracle.repository.test_locator")


class DiscoveredCandidateTest(BaseModel):
    """Normalized representation of a test related to the affected code."""
    test_file: str
    test_function: Optional[str] = None
    confidence: str = "HIGH"  # HIGH, MEDIUM, LOW
    relationship_basis: str = "NAME_AND_IMPORT_MATCH"
    content_preview: str = ""
    runnable_command: str = ""
    provenance: Dict[str, Any] = Field(default_factory=dict)


class TestLocator:
    """
    Locates tests matching target source files deterministically.
    """
    __test__ = False

    TEST_FUNC_RE = re.compile(r"^\s*def\s+(test_[a-zA-Z0-9_]+)\s*\(", re.MULTILINE)

    def __init__(self, adapter: RepositoryAdapter):
        self.adapter = adapter

    def locate_tests(
        self,
        target_file: str,
        target_function: Optional[str] = None,
    ) -> List[DiscoveredCandidateTest]:
        candidate_tests: List[DiscoveredCandidateTest] = []
        all_test_files = self.adapter.find_tests(target_file)

        stem = Path(target_file).stem.lower().replace("test_", "").replace("_test", "")
        module_name = Path(target_file).stem

        for tfile in all_test_files:
            try:
                content = self.adapter.read_file(tfile, start_line=1, end_line=150)
            except Exception:
                continue

            tfile_stem = Path(tfile).stem.lower().replace("test_", "").replace("_test", "")
            is_direct_name = (stem in tfile_stem) or (tfile_stem in stem)
            imports_symbol = (
                f"import {module_name}" in content
                or f"from {module_name}" in content
                or module_name in content
                or (target_function and target_function in content)
            )

            confidence = "LOW"
            basis = "GENERAL_TEST_SUITE"
            if is_direct_name and imports_symbol:
                confidence = "HIGH"
                basis = "DIRECT_NAME_AND_SYMBOL_IMPORT"
            elif is_direct_name:
                confidence = "HIGH"
                basis = "DIRECT_FILE_NAME_MATCH"
            elif imports_symbol:
                confidence = "MEDIUM"
                basis = "SYMBOL_IMPORT_REFERENCE"

            # Find matching test functions
            test_funcs = self.TEST_FUNC_RE.findall(content)
            matched_func = None
            if target_function:
                # Find test function that mentions the target function
                for tf in test_funcs:
                    if target_function.lower() in tf.lower():
                        matched_func = tf
                        break

            if not matched_func and test_funcs:
                matched_func = test_funcs[0]

            cmd = f"pytest {tfile}"
            if matched_func:
                cmd = f"pytest {tfile}::{matched_func} -v"

            candidate_tests.append(
                DiscoveredCandidateTest(
                    test_file=tfile,
                    test_function=matched_func,
                    confidence=confidence,
                    relationship_basis=basis,
                    content_preview=content[:200].strip(),
                    runnable_command=cmd,
                    provenance={
                        "target_file": target_file,
                        "test_file": tfile,
                        "matched_function": matched_func,
                        "is_direct_name": is_direct_name,
                        "imports_symbol": imports_symbol,
                    },
                )
            )

        # Sort: HIGH first, then MEDIUM, then LOW
        priority = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
        candidate_tests.sort(key=lambda x: priority.get(x.confidence, 3))
        return candidate_tests
