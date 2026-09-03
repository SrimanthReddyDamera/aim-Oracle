"""
ORACLE Evidence Provider Registry (Brick 3.9)
Thread-safe catalog for managing independent retrieval providers,
capability discovery, and health status monitoring.
"""

from enum import Enum
import threading
from typing import Dict, List, Optional, Set

from backend.retrieval.provider import EvidenceProvider, ProviderCapability


class ProviderStatus(str, Enum):
    """Runtime operational status of a registered provider."""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    CIRCUIT_OPEN = "circuit_open"
    OFFLINE = "offline"


class EvidenceProviderRegistry:
    """
    Catalog for registering and managing heterogeneous evidence providers.
    Enables dynamic capability discovery and safe runtime retrieval dispatch.
    """

    def __init__(self):
        self._lock = threading.RLock()
        self._providers: Dict[str, EvidenceProvider] = {}
        self._statuses: Dict[str, ProviderStatus] = {}
        self._default_provider_id: Optional[str] = None

    def register(self, provider: EvidenceProvider, is_default: bool = False) -> None:
        """Register an EvidenceProvider instance."""
        with self._lock:
            pid = provider.provider_id
            self._providers[pid] = provider
            self._statuses[pid] = ProviderStatus.HEALTHY
            if is_default or self._default_provider_id is None:
                self._default_provider_id = pid

    def unregister(self, provider_id: str) -> bool:
        """Unregister a provider by ID."""
        with self._lock:
            if provider_id in self._providers:
                del self._providers[provider_id]
                self._statuses.pop(provider_id, None)
                if self._default_provider_id == provider_id:
                    self._default_provider_id = next(iter(self._providers), None)
                return True
            return False

    def get(self, provider_id: str) -> Optional[EvidenceProvider]:
        """Retrieve a registered provider by its identifier."""
        with self._lock:
            return self._providers.get(provider_id)

    def get_default(self) -> Optional[EvidenceProvider]:
        """Retrieve the default designated provider."""
        with self._lock:
            if self._default_provider_id:
                return self._providers.get(self._default_provider_id)
            return next(iter(self._providers.values()), None)

    def list_providers(self) -> List[str]:
        """Return IDs of all registered providers."""
        with self._lock:
            return list(self._providers.keys())

    def get_all(self) -> List[EvidenceProvider]:
        """Return list of all registered provider instances."""
        with self._lock:
            return list(self._providers.values())

    def get_by_capability(self, capability: ProviderCapability) -> List[EvidenceProvider]:
        """Discover all providers that support a specific capability."""
        with self._lock:
            return [
                p for p in self._providers.values()
                if capability in p.capabilities
            ]

    def set_status(self, provider_id: str, status: ProviderStatus) -> None:
        """Update provider health/circuit status."""
        with self._lock:
            if provider_id in self._statuses:
                self._statuses[provider_id] = status

    def get_status(self, provider_id: str) -> ProviderStatus:
        """Get provider runtime status."""
        with self._lock:
            return self._statuses.get(provider_id, ProviderStatus.OFFLINE)

    def health_check_all(self) -> Dict[str, bool]:
        """Execute health checks across all registered providers."""
        with self._lock:
            results: Dict[str, bool] = {}
            for pid, p in self._providers.items():
                try:
                    is_healthy = p.health_check()
                    results[pid] = is_healthy
                    self._statuses[pid] = ProviderStatus.HEALTHY if is_healthy else ProviderStatus.OFFLINE
                except Exception:
                    results[pid] = False
                    self._statuses[pid] = ProviderStatus.OFFLINE
            return results
