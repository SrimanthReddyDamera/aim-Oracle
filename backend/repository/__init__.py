"""
ORACLE 5.0 Repository Investigation Subsystem

Exports:
- RepositoryAdapter, LocalGitRepositoryAdapter
- RepositorySecuritySandbox, SecurityValidationError, ResourceLimitExceededError
- RepositoryInventoryScanner, RepositoryInventory
- StackTraceParser, NormalizedError, StackFrame
- CodeLocator, LocalizedCode
- PythonAstAnalyzer, AstAnalysisResult
- CallGraphBuilder, CodeRelationship
- GitHistoryAnalyzer, GitInvestigationResult
- TestLocator, DiscoveredCandidateTest
- LogCorrelator, CorrelatedLogResult
- RepositoryEvidenceBuilder, GeneratedEvidencePackage
- RealRepositoryInvestigationEngine, RealInvestigationRequest
"""

from backend.repository.adapter import LocalGitRepositoryAdapter, RepositoryAdapter
from backend.repository.ast_analyzer import AstAnalysisResult, PythonAstAnalyzer
from backend.repository.call_graph import CallGraphBuilder, CodeRelationship
from backend.repository.engine import RealInvestigationRequest, RealRepositoryInvestigationEngine
from backend.repository.evidence_builder import GeneratedEvidencePackage, RepositoryEvidenceBuilder
from backend.repository.git_analyzer import GitHistoryAnalyzer, GitInvestigationResult
from backend.repository.inventory import RepositoryInventory, RepositoryInventoryScanner
from backend.repository.locator import CodeLocator, LocalizedCode
from backend.repository.log_correlator import CorrelatedLogResult, LogCorrelator
from backend.repository.parser import NormalizedError, StackFrame, StackTraceParser
from backend.repository.security import (
    RepositorySecuritySandbox,
    ResourceLimitExceededError,
    SecurityValidationError,
)
from backend.repository.test_locator import DiscoveredCandidateTest, TestLocator

__all__ = [
    "RepositoryAdapter",
    "LocalGitRepositoryAdapter",
    "RepositorySecuritySandbox",
    "SecurityValidationError",
    "ResourceLimitExceededError",
    "RepositoryInventoryScanner",
    "RepositoryInventory",
    "StackTraceParser",
    "NormalizedError",
    "StackFrame",
    "CodeLocator",
    "LocalizedCode",
    "PythonAstAnalyzer",
    "AstAnalysisResult",
    "CallGraphBuilder",
    "CodeRelationship",
    "GitHistoryAnalyzer",
    "GitInvestigationResult",
    "TestLocator",
    "DiscoveredCandidateTest",
    "LogCorrelator",
    "CorrelatedLogResult",
    "RepositoryEvidenceBuilder",
    "GeneratedEvidencePackage",
    "RealRepositoryInvestigationEngine",
    "RealInvestigationRequest",
]
