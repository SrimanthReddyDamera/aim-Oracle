"""
Provider-Neutral Secret Management Interface (Brick 4.6)

Decouples credential storage from cloud vendors and filesystems.
Provides pluggable implementations:
- EnvironmentSecretStore: reads from os.environ
- KubernetesSecretStore: reads from mounted Secret volumes (/etc/oracle/secrets/)
- InMemorySecretStore: deterministic testing store
- Secret redaction and token masking utilities
"""

from __future__ import annotations

import abc
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional


class SecretStore(abc.ABC):
    """Abstract interface for enterprise secret storage."""

    @abc.abstractmethod
    def get_secret(self, key: str, default: Optional[str] = None) -> Optional[str]:
        """Retrieve secret by key."""
        raise NotImplementedError

    @abc.abstractmethod
    def set_secret(self, key: str, value: str) -> None:
        """Store or update secret."""
        raise NotImplementedError

    @abc.abstractmethod
    def delete_secret(self, key: str) -> bool:
        """Remove secret from store."""
        raise NotImplementedError

    @abc.abstractmethod
    def list_keys(self) -> List[str]:
        """List available secret keys (names only, never values)."""
        raise NotImplementedError


class EnvironmentSecretStore(SecretStore):
    """Secret store backed by process environment variables."""

    def __init__(self, prefix: str = ""):
        self.prefix = prefix

    def _format_key(self, key: str) -> str:
        k = key.upper().replace("-", "_").replace(".", "_")
        return f"{self.prefix}{k}" if self.prefix else k

    def get_secret(self, key: str, default: Optional[str] = None) -> Optional[str]:
        env_key = self._format_key(key)
        val = os.getenv(env_key)
        if val is not None:
            return val
        # Also check without prefix if prefix was set
        if self.prefix:
            val_no_pref = os.getenv(key.upper().replace("-", "_").replace(".", "_"))
            if val_no_pref is not None:
                return val_no_pref
        return default

    def set_secret(self, key: str, value: str) -> None:
        env_key = self._format_key(key)
        os.environ[env_key] = value

    def delete_secret(self, key: str) -> bool:
        env_key = self._format_key(key)
        if env_key in os.environ:
            del os.environ[env_key]
            return True
        return False

    def list_keys(self) -> List[str]:
        if not self.prefix:
            return list(os.environ.keys())
        return [k[len(self.prefix):] for k in os.environ.keys() if k.startswith(self.prefix)]


class KubernetesSecretStore(SecretStore):
    """
    Secret store reading from Kubernetes mounted Secret volumes (e.g. /etc/oracle/secrets/).
    Falls back to environment variables if file is absent.
    """

    def __init__(self, mount_path: str = "/etc/oracle/secrets", fallback_to_env: bool = True):
        self.mount_path = Path(mount_path)
        self.fallback_to_env = fallback_to_env
        self._env_store = EnvironmentSecretStore() if fallback_to_env else None

    def get_secret(self, key: str, default: Optional[str] = None) -> Optional[str]:
        sanitized_filename = key.replace("/", "_").replace("\\", "_")
        secret_file = self.mount_path / sanitized_filename
        if secret_file.is_file():
            try:
                return secret_file.read_text(encoding="utf-8").strip()
            except Exception:
                pass

        if self._env_store:
            return self._env_store.get_secret(key, default=default)

        return default

    def set_secret(self, key: str, value: str) -> None:
        """In Kubernetes, secret volume mounts are typically read-only. We update fallback or write if writable."""
        try:
            self.mount_path.mkdir(parents=True, exist_ok=True)
            secret_file = self.mount_path / key
            secret_file.write_text(value, encoding="utf-8")
        except Exception:
            if self._env_store:
                self._env_store.set_secret(key, value)

    def delete_secret(self, key: str) -> bool:
        secret_file = self.mount_path / key
        deleted = False
        if secret_file.exists():
            try:
                secret_file.unlink()
                deleted = True
            except Exception:
                pass
        if self._env_store and self._env_store.delete_secret(key):
            deleted = True
        return deleted

    def list_keys(self) -> List[str]:
        keys = set()
        if self.mount_path.is_dir():
            for p in self.mount_path.iterdir():
                if p.is_file() and not p.name.startswith("."):
                    keys.add(p.name)
        if self._env_store:
            keys.update(self._env_store.list_keys())
        return sorted(keys)


class InMemorySecretStore(SecretStore):
    """In-memory secret store for isolated unit tests."""

    def __init__(self, initial_secrets: Optional[Dict[str, str]] = None):
        self._secrets: Dict[str, str] = dict(initial_secrets or {})

    def get_secret(self, key: str, default: Optional[str] = None) -> Optional[str]:
        return self._secrets.get(key, default)

    def set_secret(self, key: str, value: str) -> None:
        self._secrets[key] = value

    def delete_secret(self, key: str) -> bool:
        return self._secrets.pop(key, None) is not None

    def list_keys(self) -> List[str]:
        return sorted(self._secrets.keys())


# -----------------------------------------------------------------------------
# SECRET REDACTION & MASKING UTILITIES
# -----------------------------------------------------------------------------

SENSITIVE_KEY_PATTERNS = re.compile(
    r"(secret|token|password|auth|authorization|key|credential|private)",
    re.IGNORECASE,
)


def mask_token(token: Optional[str], visible_chars: int = 4) -> str:
    """Mask sensitive token, leaving only tail characters visible."""
    if not token:
        return ""
    if len(token) <= visible_chars:
        return "***"
    return f"{'*' * (len(token) - visible_chars)}{token[-visible_chars:]}"


def redact_sensitive_payload(data: Any) -> Any:
    """Recursively scrub sensitive keys and tokens from dict/list structures."""
    if isinstance(data, dict):
        scrubbed = {}
        for k, v in data.items():
            if SENSITIVE_KEY_PATTERNS.search(str(k)):
                scrubbed[k] = "***REDACTED***"
            else:
                scrubbed[k] = redact_sensitive_payload(v)
        return scrubbed
    elif isinstance(data, list):
        return [redact_sensitive_payload(item) for item in data]
    return data
