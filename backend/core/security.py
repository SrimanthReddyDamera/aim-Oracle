"""
ORACLE Security & Secrets Sanitization Module (Brick 3.10)
Ensures credentials, API tokens, passwords, and authorization headers are never
leaked in telemetry, logs, traces, exception messages, or diagnostics.
"""

import os
import re
from typing import Any, Dict, Optional, Set


# Sensitive key identifiers commonly found in configuration or telemetry
SENSITIVE_KEY_PATTERNS = re.compile(
    r"(?:token|secret|password|auth|credential|api[_-]?key|bearer|access[_-]?token|private[_-]?key)",
    re.IGNORECASE,
)

# Generic pattern matching Bearer tokens, GitHub PATs, Jira tokens, or base64 Basic Auth
BEARER_AUTH_PATTERN = re.compile(r"(Bearer\s+)[A-Za-z0-9_\.\-]+", re.IGNORECASE)
BASIC_AUTH_PATTERN = re.compile(r"(Basic\s+)[A-Za-z0-9+/=]+", re.IGNORECASE)
GENERIC_PAT_PATTERN = re.compile(r"(ghp_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})", re.IGNORECASE)


def mask_secret(secret: Optional[str], keep_prefix: int = 4, keep_suffix: int = 4) -> str:
    """
    Mask a sensitive secret string, preserving short prefix/suffix if long enough.
    Example: 'ghp_1234567890abcdef' -> 'ghp_***cdef'
    """
    if not secret:
        return ""
    s_len = len(secret)
    if s_len <= (keep_prefix + keep_suffix + 2):
        return "***REDACTED***"
    return f"{secret[:keep_prefix]}***{secret[-keep_suffix:]}"


def redact_sensitive_text(text: str, known_secrets: Optional[Set[str]] = None) -> str:
    """
    Scrub sensitive credentials, tokens, and authorization headers from raw text.
    """
    if not text:
        return text

    sanitized = text

    # Redact known active secrets from environment or parameters if provided
    if known_secrets:
        for sec in known_secrets:
            if sec and len(sec) >= 6:  # avoid scrubbing trivial short substrings
                sanitized = sanitized.replace(sec, mask_secret(sec))

    # Redact common auth patterns
    sanitized = BEARER_AUTH_PATTERN.sub(r"\1***REDACTED***", sanitized)
    sanitized = BASIC_AUTH_PATTERN.sub(r"\1***REDACTED***", sanitized)
    sanitized = GENERIC_PAT_PATTERN.sub(r"***REDACTED_PAT***", sanitized)

    return sanitized


def redact_sensitive_data(
    data: Any,
    known_secrets: Optional[Set[str]] = None,
    depth: int = 0,
    max_depth: int = 10,
) -> Any:
    """
    Recursively sanitize dictionaries, lists, and strings to strip any secret values.
    """
    if depth > max_depth:
        return data

    if isinstance(data, str):
        return redact_sensitive_text(data, known_secrets=known_secrets)

    if isinstance(data, dict):
        cleaned: Dict[str, Any] = {}
        for k, v in data.items():
            k_str = str(k)
            if SENSITIVE_KEY_PATTERNS.search(k_str):
                cleaned[k_str] = "***REDACTED***" if v else ""
            else:
                cleaned[k_str] = redact_sensitive_data(v, known_secrets=known_secrets, depth=depth + 1)
        return cleaned

    if isinstance(data, (list, tuple, set)):
        items = [redact_sensitive_data(item, known_secrets=known_secrets, depth=depth + 1) for item in data]
        if isinstance(data, tuple):
            return tuple(items)
        if isinstance(data, set):
            return set(items)
        return items

    return data


def get_active_env_secrets() -> Set[str]:
    """
    Extract current runtime secrets from environment variables for active scrubbing.
    """
    secrets: Set[str] = set()
    env_keys = [
        "JIRA_API_TOKEN",
        "GITHUB_API_TOKEN",
        "GITHUB_TOKEN",
        "API_KEY",
        "SECRET_KEY",
        "PASSWORD",
    ]
    for k in env_keys:
        val = os.getenv(k)
        if val and len(val.strip()) >= 6:
            secrets.add(val.strip())
    return secrets
