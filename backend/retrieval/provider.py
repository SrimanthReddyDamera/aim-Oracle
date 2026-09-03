"""
ORACLE Evidence Provider Abstraction (Brick 3.4)
Generic retrieval provider contract decoupling the Investigation Controller
from underlying data sources (documents, Jira, GitHub, Slack, etc.).
"""

from abc import ABC, abstractmethod
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple
from pydantic import BaseModel, Field

from backend.evidence.models import Evidence


class ProviderCapability(str, Enum):
    """Declared capabilities supported by an EvidenceProvider."""
    LEXICAL_SEARCH = "lexical_search"
    SEMANTIC_SEARCH = "semantic_search"
    STRUCTURED_FILTER = "structured_filter"
    ENTITY_LOOKUP = "entity_lookup"
    LOCAL_CACHE = "local_cache"
    NETWORK_REMOTE = "network_remote"


class ProviderSearchResult(BaseModel):
    """Normalized search result across any enterprise or document provider."""
    evidence_id: str
    source_type: str = "document"  # "document", "jira", "linear", "github", "slack"
    source_id: str
    content: str
    uri: Optional[str] = None
    timestamp: Optional[str] = None
    score: float = 0.0
    metadata: Dict[str, Any] = Field(default_factory=dict)
    evidence: Optional[Evidence] = None


class EvidenceProvider(ABC):
    """
    Abstract interface for all retrieval providers.
    Ensures that future providers (Jira, Linear, GitHub, Slack) plug into the
    Investigation Controller without modifying investigation logic.
    """

    @property
    @abstractmethod
    def provider_id(self) -> str:
        """Unique identifier for this provider instance (e.g. 'sqlite_fts5', 'jira', 'slack')."""
        pass

    @property
    @abstractmethod
    def capabilities(self) -> Set[ProviderCapability]:
        """Set of capabilities supported by this provider."""
        pass

    @abstractmethod
    def search(
        self,
        query: str,
        k: int = 5,
        filters: Optional[Dict[str, Any]] = None,
    ) -> Tuple[List[Tuple[Evidence, float]], float]:
        """
        Execute search query across the provider's backing data.
        Returns: ([(Evidence, score)], elapsed_latency_ms)
        """
        pass

    @abstractmethod
    def search_provider(
        self,
        query: str,
        k: int = 4,
        filters: Optional[Dict[str, Any]] = None,
    ) -> List[ProviderSearchResult]:
        """Execute search returning normalized ProviderSearchResult instances."""
        pass

    @abstractmethod
    def health_check(self) -> bool:
        """Verify backing service connectivity and availability."""
        pass
