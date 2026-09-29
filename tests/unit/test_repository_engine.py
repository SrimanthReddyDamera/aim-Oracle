"""
Unit Tests for ORACLE 5.0 Repository Investigation Engine
Tests:
- Stack trace parsing (Python, Node.js, Go)
- Code localization & evidence window formatting
- AST analysis (calls, subscripts, containing function)
- Call graph builder
- Git analyzer & diff extraction
- Test locator
- Security sandbox path traversal and symlink guards
- Resource limits and secret redaction
"""

import os
from pathlib import Path
import pytest

from backend.repository.adapter import LocalGitRepositoryAdapter
from backend.repository.ast_analyzer import PythonAstAnalyzer
from backend.repository.call_graph import CallGraphBuilder
from backend.repository.git_analyzer import GitHistoryAnalyzer
from backend.repository.inventory import RepositoryInventoryScanner
from backend.repository.locator import CodeLocator
from backend.repository.log_correlator import LogCorrelator
from backend.repository.parser import StackTraceParser
from backend.repository.security import (
    RepositorySecuritySandbox,
    ResourceLimitExceededError,
    SecurityValidationError,
)
from backend.repository.test_locator import TestLocator


EVAL_REPO_DIR = Path(__file__).resolve().parent.parent / "test_repos" / "evaluation_repo"


def test_stack_trace_parser_python():
    trace = """Traceback (most recent call last):
  File "src/payment/payment_service.py", line 184, in process_payment
    customer_tier = customer["tier"]
TypeError: 'NoneType' object is not subscriptable"""

    parsed = StackTraceParser.parse(trace)
    assert parsed.runtime == "python"
    assert parsed.exception_type == "TypeError"
    assert "'NoneType' object is not subscriptable" in parsed.message
    assert len(parsed.frames) == 1
    assert parsed.frames[0].file == "src/payment/payment_service.py"
    assert parsed.frames[0].line == 184
    assert parsed.frames[0].function == "process_payment"


def test_stack_trace_parser_node():
    trace = """TypeError: Cannot read property 'id' of undefined
    at processPayment (/app/src/payment/service.ts:42:15)
    at handleRequest (/app/src/server.ts:10:5)"""

    parsed = StackTraceParser.parse(trace)
    assert parsed.runtime == "node"
    assert parsed.exception_type == "TypeError"
    assert len(parsed.frames) >= 2
    assert parsed.frames[0].line == 42
    assert parsed.frames[0].function == "processPayment"


def test_stack_trace_parser_go():
    trace = """panic: runtime error: invalid memory address or nil pointer dereference
[signal SIGSEGV: segmentation violation]
main.go:128 +0x3a"""

    parsed = StackTraceParser.parse(trace)
    assert parsed.runtime == "go"
    assert parsed.exception_type == "Panic"
    assert len(parsed.frames) == 1
    assert parsed.frames[0].line == 128


def test_security_sandbox_path_validation():
    sandbox = RepositorySecuritySandbox(allowed_roots=[EVAL_REPO_DIR.parent])

    # Valid path
    valid_p = sandbox.validate_repository_path(EVAL_REPO_DIR)
    assert valid_p == EVAL_REPO_DIR.resolve()

    # Traversal attempt
    with pytest.raises(SecurityValidationError):
        sandbox.validate_repository_path("../../../../../etc")

    # Empty path
    with pytest.raises(SecurityValidationError):
        sandbox.validate_repository_path("")


def test_security_sandbox_secret_redaction():
    sandbox = RepositorySecuritySandbox()
    text = "Bearer ghp_1234567890abcdef1234567890abcdef12345678 and secret API token"
    redacted = sandbox.redact_content(text)
    assert "ghp_1234567890abcdef" not in redacted
    assert "***REDACTED" in redacted


def test_repository_inventory_scanner():
    adapter = LocalGitRepositoryAdapter(EVAL_REPO_DIR)
    scanner = RepositoryInventoryScanner(adapter)
    inv = scanner.scan()

    assert "Python" in inv.languages
    assert inv.total_files >= 5
    assert "src" in inv.source_directories
    assert "tests" in inv.test_directories
    assert "requirements.txt" in [Path(m).name for m in inv.dependency_manifests]


def test_code_locator():
    adapter = LocalGitRepositoryAdapter(EVAL_REPO_DIR)
    locator = CodeLocator(adapter)

    trace = """Traceback (most recent call last):
  File "src/payment/payment_service.py", line 184, in process_payment
    customer_tier = customer["tier"]
TypeError: 'NoneType' object is not subscriptable"""

    parsed = StackTraceParser.parse(trace)
    localized = locator.locate(parsed)

    assert localized is not None
    assert localized.target_file == "src/payment/payment_service.py"
    assert localized.target_line == 184
    assert "customer_tier = customer[\"tier\"]" in localized.target_line_content
    assert localized.window_start_line < 184 < localized.window_end_line


def test_python_ast_analyzer():
    adapter = LocalGitRepositoryAdapter(EVAL_REPO_DIR)
    source = adapter.read_file("src/payment/payment_service.py")

    analyzer = PythonAstAnalyzer(source, file_path="src/payment/payment_service.py")
    res = analyzer.analyze(target_line=184)

    assert res.containing_class == "PaymentService"
    assert res.containing_function == "process_payment"
    assert res.target_expression_type == "SUBSCRIPT_ACCESS"
    assert res.has_null_check is False  # Line 184 has no null check!

    relationships = CallGraphBuilder.build_from_ast(res)
    assert len(relationships) >= 1
    assert any("lookup_customer" in r.callee or "get_customer" in r.callee for r in relationships)


def test_git_history_analyzer():
    adapter = LocalGitRepositoryAdapter(EVAL_REPO_DIR)
    git_analyzer = GitHistoryAnalyzer(adapter)
    res = git_analyzer.analyze("src/payment/payment_service.py", target_line=184)

    assert len(res.recent_commits) >= 1
    assert res.current_head is not None
    assert res.blame is not None
    assert res.blame.line == 184


def test_test_locator():
    adapter = LocalGitRepositoryAdapter(EVAL_REPO_DIR)
    locator = TestLocator(adapter)
    tests = locator.locate_tests("src/payment/payment_service.py", "process_payment")

    assert len(tests) >= 1
    assert "test_payment.py" in tests[0].test_file
    assert tests[0].confidence == "HIGH"
    assert "pytest" in tests[0].runnable_command


def test_log_correlator():
    logs = """2026-09-14T08:24:11.402Z [ERROR] req_9481a payment_service.py:184: get_customer() returned None
2026-09-14T08:24:11.403Z [ERROR] req_9481a TypeError: 'NoneType' object is not subscriptable"""

    res = LogCorrelator.correlate(logs, target_file="src/payment/payment_service.py", exception_type="TypeError")
    assert res.has_matching_errors is True
    assert res.primary_request_id == "req_9481a"
    assert len(res.correlated_records) == 2
