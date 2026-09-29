"""
Provider-Agnostic Credential Architecture & Secret Redaction (Brick 4.1)

Enforces zero-secret leakage across ORACLE:
1. CredentialProvider interface (token access, expiration, rotation, scopes)
2. EnvCredentialProvider (reads environment variables without hardcoding)
3. InMemoryCredentialVault (thread-safe, TTL, least-privilege scopes, runtime injection)
4. SecretRedactor (scrubs secrets from strings, dictionaries, Evidence, logs, traces)
"""

from __future__ import annotations

import os
import re
import threading
import time
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Set


# -----------------------------------------------------------------------------
# 1. CREDENTIAL PROVIDER INTERFACE
# -----------------------------------------------------------------------------

class CredentialProvider(ABC):
    """Abstract contract for secure provider credential management."""

    @abstractmethod
    def get_token(self, provider_id: str, scope: Optional[str] = None) -> Optional[str]:
        """Retrieve active token for provider, verifying scope if specified."""
        pass

    @abstractmethod
    def validate_token(self, provider_id: str) -> bool:
        """Check if provider has a valid, non-expired credential available."""
        pass

    @abstractmethod
    def rotate_token(self, provider_id: str, new_token: str, expires_at: Optional[float] = None) -> bool:
        """Rotate token for provider."""
        pass

    @abstractmethod
    def is_expired(self, provider_id: str) -> bool:
        """Check if provider's token is expired."""
        pass


# -----------------------------------------------------------------------------
# 2. SECRET REDACTOR
# -----------------------------------------------------------------------------

class SecretRedactor:
    """
    Central registry for scrubbing tokens, secrets, and authorization signatures.
    Guarantees credentials never appear in Evidence, logs, or error traces.
    """

    def __init__(self):
        self._lock = threading.RLock()
        self._known_secrets: Set[str] = set()

    def register_secret(self, secret: str) -> None:
        """Register a secret string to be scrubbed."""
        if secret and len(secret.strip()) >= 6:
            with self._lock:
                self._known_secrets.add(secret.strip())

    def redact(self, text: str) -> str:
        """Redact known secrets and common token patterns from text."""
        if not text:
            return ""

        result = text
        with self._lock:
            # 1. Scrub exact known secrets
            for secret in self._known_secrets:
                if secret in result:
                    result = result.replace(secret, "[REDACTED_SECRET]")

        # 2. Scrub standard pattern signatures
        # Bearer tokens / GitHub tokens (ghp_, ghs_, gho_, github_pat_)
        result = re.sub(r"(Bearer\s+)[A-Za-z0-9_\-\.]{8,}", r"\1[REDACTED_BEARER]", result, flags=re.IGNORECASE)
        result = re.sub(r"(gh[pso]_[A-Za-z0-9_]{20,})", r"[REDACTED_GITHUB_TOKEN]", result)
        result = re.sub(r"(github_pat_[A-Za-z0-9_]{20,})", r"[REDACTED_GITHUB_PAT]", result)
        # Jira / basic auth tokens
        result = re.sub(r"(Basic\s+)[A-Za-z0-9+/=]{10,}", r"\1[REDACTED_BASIC_AUTH]", result, flags=re.IGNORECASE)
        # Query params
        result = re.sub(r"((?:token|key|api_key|secret|password)=)[^&\s]+", r"\1[REDACTED_PARAM]", result, flags=re.IGNORECASE)

        return result

    def redact_dict(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Recursively redact dictionary keys and values."""
        clean: Dict[str, Any] = {}
        for k, v in data.items():
            if any(term in k.lower() for term in ["token", "secret", "password", "key", "authorization"]):
                clean[k] = "[REDACTED]"
            elif isinstance(v, str):
                clean[k] = self.redact(v)
            elif isinstance(v, dict):
                clean[k] = self.redact_dict(v)
            elif isinstance(v, list):
                clean[k] = [self.redact(item) if isinstance(item, str) else item for item in v]
            else:
                clean[k] = v
        return clean


# Global redactor instance
GLOBAL_REDACTOR = SecretRedactor()


# -----------------------------------------------------------------------------
# 3. ENVIRONMENT CREDENTIAL PROVIDER
# -----------------------------------------------------------------------------

class EnvCredentialProvider(CredentialProvider):
    """
    Retrieves credentials from environment variables.
    Defaults to standard enterprise variable conventions.
    """

    DEFAULT_ENV_MAPPING: Dict[str, List[str]] = {
        "github": ["GITHUB_TOKEN", "GH_TOKEN"],
        "jira": ["JIRA_API_TOKEN", "JIRA_TOKEN"],
        "github_actions": ["GITHUB_TOKEN", "GH_TOKEN"],
        "semgrep": ["SEMGREP_APP_TOKEN", "SEMGREP_TOKEN"],
        "trivy": ["TRIVY_AUTH_TOKEN", "TRIVY_TOKEN"],
    }

    def __init__(self, mapping: Optional[Dict[str, List[str]]] = None):
        self.mapping = mapping or dict(self.DEFAULT_ENV_MAPPING)

    def get_token(self, provider_id: str, scope: Optional[str] = None) -> Optional[str]:
        keys = self.mapping.get(provider_id.lower(), [f"{provider_id.upper()}_TOKEN"])
        for key in keys:
            val = os.environ.get(key)
            if val and val.strip():
                token = val.strip()
                GLOBAL_REDACTOR.register_secret(token)
                return token
        return None

    def validate_token(self, provider_id: str) -> bool:
        return self.get_token(provider_id) is not None

    def rotate_token(self, provider_id: str, new_token: str, expires_at: Optional[float] = None) -> bool:
        keys = self.mapping.get(provider_id.lower(), [f"{provider_id.upper()}_TOKEN"])
        primary_key = keys[0]
        os.environ[primary_key] = new_token.strip()
        GLOBAL_REDACTOR.register_secret(new_token.strip())
        return True

    def is_expired(self, provider_id: str) -> bool:
        # Env vars do not have automatic TTL unless externally tracked
        return not self.validate_token(provider_id)


# -----------------------------------------------------------------------------
# 4. IN-MEMORY CREDENTIAL VAULT (FOR TESTS & RUNTIME DYNAMIC INJECTION)
# -----------------------------------------------------------------------------

class VaultTokenRecord:
    def __init__(self, token: str, expires_at: Optional[float] = None, scopes: Optional[List[str]] = None):
        self.token = token
        self.expires_at = expires_at
        self.scopes = set(scopes) if scopes is not None else {"*"}
        self.created_at = time.time()


class InMemoryCredentialVault(CredentialProvider):
    """
    Thread-safe in-memory vault for secure token lifecycle testing.
    Supports TTL expiration, rotation, and least-privilege scope checks.
    """

    def __init__(self):
        self._lock = threading.RLock()
        self._vault: Dict[str, VaultTokenRecord] = {}

    def register_token(
        self,
        provider_id: str,
        token: str,
        expires_at: Optional[float] = None,
        scopes: Optional[List[str]] = None,
    ) -> None:
        """Register a token in the vault."""
        with self._lock:
            cleaned = token.strip()
            GLOBAL_REDACTOR.register_secret(cleaned)
            self._vault[provider_id.lower()] = VaultTokenRecord(
                token=cleaned,
                expires_at=expires_at,
                scopes=scopes,
            )

    def get_token(self, provider_id: str, scope: Optional[str] = None) -> Optional[str]:
        with self._lock:
            record = self._vault.get(provider_id.lower())
            if not record:
                return None

            # Check expiration
            if record.expires_at is not None and time.time() > record.expires_at:
                return None

            # Check scope if specified
            if scope and scope not in record.scopes and "*" not in record.scopes:
                return None

            return record.token

    def validate_token(self, provider_id: str) -> bool:
        return self.get_token(provider_id) is not None

    def rotate_token(self, provider_id: str, new_token: str, expires_at: Optional[float] = None) -> bool:
        with self._lock:
            existing = self._vault.get(provider_id.lower())
            scopes = list(existing.scopes) if existing else []
            self.register_token(provider_id, new_token, expires_at=expires_at, scopes=scopes)
            return True

    def is_expired(self, provider_id: str) -> bool:
        with self._lock:
            record = self._vault.get(provider_id.lower())
            if not record:
                return True
            if record.expires_at is not None and time.time() > record.expires_at:
                return True
            return False

    def revoke_token(self, provider_id: str) -> bool:
        with self._lock:
            return self._vault.pop(provider_id.lower(), None) is not None
