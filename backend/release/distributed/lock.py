"""
Distributed Locking & Fencing Architecture (Brick 4.5)

Provides provider-neutral distributed locking with:
1. Monotonic fencing tokens (prevents stale workers from writing authoritative state).
2. Owner verification, bounded TTL, explicit renew(), and safe release().
3. RedisDistributedLockProvider (Lua script atomic operations & Redis fencing counter).
4. DatabaseDistributedLockProvider (fallback to PostgreSQL / SQLite distributed_locks table).
5. InMemoryDistributedLockProvider (for offline unit tests).
"""

from __future__ import annotations

import logging
import time
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Dict, Optional

logger = logging.getLogger("oracle.distributed.lock")


@dataclass
class LockToken:
    """Opaque distributed lock token carrying identity and a monotonic fencing token."""
    key: str
    owner: str
    fencing_token: int
    expires_at: float
    tenant_id: str = "default"

    @property
    def is_expired(self) -> bool:
        return time.time() >= self.expires_at


class DistributedLockProvider(ABC):
    """Abstract contract for distributed locks with fencing tokens."""

    @abstractmethod
    def acquire(
        self,
        key: str,
        owner: str,
        ttl_seconds: float = 30.0,
        tenant_id: str = "default",
    ) -> Optional[LockToken]:
        """
        Attempt to acquire lock.
        Returns LockToken with monotonic fencing token if successful, None if locked.
        """
        pass

    @abstractmethod
    def renew(
        self,
        token: LockToken,
        ttl_seconds: float = 30.0,
    ) -> bool:
        """Extend lock lease before expiration."""
        pass

    @abstractmethod
    def release(
        self,
        token: LockToken,
    ) -> bool:
        """Release lock safely. Fails if token has been superseded or expired."""
        pass

    @abstractmethod
    def is_locked(self, key: str, tenant_id: str = "default") -> bool:
        """Check if lock key is currently held by an active owner."""
        pass

    @abstractmethod
    def get_current_fencing_token(self, key: str, tenant_id: str = "default") -> int:
        """Retrieve highest known fencing token for key."""
        pass


# -----------------------------------------------------------------------------
# 1. IN-MEMORY DISTRIBUTED LOCK PROVIDER (LOCAL / OFFLINE)
# -----------------------------------------------------------------------------

class InMemoryDistributedLockProvider(DistributedLockProvider):
    """Thread-safe in-memory lock provider for deterministic testing."""

    def __init__(self):
        import threading
        self._lock = threading.RLock()
        self._locks: Dict[str, LockToken] = {}
        self._fencing_counters: Dict[str, int] = {}

    def _scoped_key(self, key: str, tenant_id: str) -> str:
        return f"{tenant_id}:{key}"

    def acquire(
        self,
        key: str,
        owner: str,
        ttl_seconds: float = 30.0,
        tenant_id: str = "default",
    ) -> Optional[LockToken]:
        scoped = self._scoped_key(key, tenant_id)
        now = time.time()
        with self._lock:
            existing = self._locks.get(scoped)
            if existing and not existing.is_expired:
                # Still locked by active owner
                if existing.owner == owner:
                    # Idempotent re-acquisition
                    existing.expires_at = now + ttl_seconds
                    return existing
                return None

            # Increment monotonic fencing token
            fencing = self._fencing_counters.get(scoped, 0) + 1
            self._fencing_counters[scoped] = fencing

            token = LockToken(
                key=key,
                owner=owner,
                fencing_token=fencing,
                expires_at=now + ttl_seconds,
                tenant_id=tenant_id,
            )
            self._locks[scoped] = token
            return token

    def renew(self, token: LockToken, ttl_seconds: float = 30.0) -> bool:
        scoped = self._scoped_key(token.key, token.tenant_id)
        now = time.time()
        with self._lock:
            existing = self._locks.get(scoped)
            if not existing or existing.is_expired:
                return False
            if existing.owner != token.owner or existing.fencing_token != token.fencing_token:
                return False  # Lock ownership was stolen or superseded
            existing.expires_at = now + ttl_seconds
            token.expires_at = existing.expires_at
            return True

    def release(self, token: LockToken) -> bool:
        scoped = self._scoped_key(token.key, token.tenant_id)
        with self._lock:
            existing = self._locks.get(scoped)
            if not existing:
                return True
            if existing.owner != token.owner or existing.fencing_token != token.fencing_token:
                return False  # Cannot release someone else's or superseded lock
            self._locks.pop(scoped, None)
            return True

    def is_locked(self, key: str, tenant_id: str = "default") -> bool:
        scoped = self._scoped_key(key, tenant_id)
        with self._lock:
            existing = self._locks.get(scoped)
            return existing is not None and not existing.is_expired

    def get_current_fencing_token(self, key: str, tenant_id: str = "default") -> int:
        scoped = self._scoped_key(key, tenant_id)
        with self._lock:
            return self._fencing_counters.get(scoped, 0)

    def clear(self) -> None:
        """Clear all held locks and fencing counters to simulate node restart or partition."""
        with self._lock:
            self._locks.clear()
            self._fencing_counters.clear()



# -----------------------------------------------------------------------------
# 2. DATABASE-BACKED DISTRIBUTED LOCK PROVIDER
# -----------------------------------------------------------------------------

class DatabaseDistributedLockProvider(DistributedLockProvider):
    """
    Distributed lock provider backed by relational database (PostgreSQL / SQLite).
    Acts as zero-dependency distributed lock when Redis is not deployed.
    """

    def __init__(self, lock_repo: Any):
        self.repo = lock_repo

    def acquire(
        self,
        key: str,
        owner: str,
        ttl_seconds: float = 30.0,
        tenant_id: str = "default",
    ) -> Optional[LockToken]:
        res = self.repo.acquire_lock(key, owner, ttl_seconds=ttl_seconds, tenant_id=tenant_id)
        if not res:
            return None
        fencing_token, expires_at = res
        return LockToken(
            key=key,
            owner=owner,
            fencing_token=fencing_token,
            expires_at=expires_at,
            tenant_id=tenant_id,
        )

    def renew(self, token: LockToken, ttl_seconds: float = 30.0) -> bool:
        success = self.repo.renew_lock(
            token.key,
            token.owner,
            token.fencing_token,
            ttl_seconds=ttl_seconds,
            tenant_id=token.tenant_id,
        )
        if success:
            token.expires_at = time.time() + ttl_seconds
        return success

    def release(self, token: LockToken) -> bool:
        return self.repo.release_lock(
            token.key,
            token.owner,
            token.fencing_token,
            tenant_id=token.tenant_id,
        )

    def is_locked(self, key: str, tenant_id: str = "default") -> bool:
        lock = self.repo.get_lock(key, tenant_id=tenant_id)
        if not lock:
            return False
        return bool(lock.get("owner")) and float(lock.get("expires_at", 0)) > time.time()

    def get_current_fencing_token(self, key: str, tenant_id: str = "default") -> int:
        lock = self.repo.get_lock(key, tenant_id=tenant_id)
        return int(lock.get("fencing_token", 0)) if lock else 0


# -----------------------------------------------------------------------------
# 3. REDIS DISTRIBUTED LOCK PROVIDER (OPTIONAL COORDINATION)
# -----------------------------------------------------------------------------

class RedisDistributedLockProvider(DistributedLockProvider):
    """
    Production-grade Redis distributed lock using atomic Lua scripts and fencing counters.
    Requires optional redis package and active Redis server.
    """

    RELEASE_LUA = """
    if redis.call("get", KEYS[1]) == ARGV[1] then
        return redis.call("del", KEYS[1])
    else
        return 0
    end
    """

    RENEW_LUA = """
    if redis.call("get", KEYS[1]) == ARGV[1] then
        return redis.call("pexpire", KEYS[1], ARGV[2])
    else
        return 0
    end
    """

    def __init__(self, redis_client: Any, key_prefix: str = "oracle:lock"):
        self.redis = redis_client
        self.key_prefix = key_prefix
        self._release_script = self.redis.register_script(self.RELEASE_LUA)
        self._renew_script = self.redis.register_script(self.RENEW_LUA)

    def _lock_key(self, key: str, tenant_id: str) -> str:
        return f"{self.key_prefix}:{tenant_id}:{key}"

    def _counter_key(self, key: str, tenant_id: str) -> str:
        return f"{self.key_prefix}:fencing:{tenant_id}:{key}"

    def acquire(
        self,
        key: str,
        owner: str,
        ttl_seconds: float = 30.0,
        tenant_id: str = "default",
    ) -> Optional[LockToken]:
        lkey = self._lock_key(key, tenant_id)
        ckey = self._counter_key(key, tenant_id)
        ttl_ms = int(ttl_seconds * 1000)

        # Monotonic fencing token
        fencing_token = self.redis.incr(ckey)
        val = f"{owner}:{fencing_token}"

        acquired = self.redis.set(lkey, val, nx=True, px=ttl_ms)
        if not acquired:
            return None

        expires_at = time.time() + ttl_seconds
        return LockToken(
            key=key,
            owner=owner,
            fencing_token=fencing_token,
            expires_at=expires_at,
            tenant_id=tenant_id,
        )

    def renew(self, token: LockToken, ttl_seconds: float = 30.0) -> bool:
        lkey = self._lock_key(token.key, token.tenant_id)
        val = f"{token.owner}:{token.fencing_token}"
        ttl_ms = int(ttl_seconds * 1000)
        res = self._renew_script(keys=[lkey], args=[val, ttl_ms])
        if bool(res):
            token.expires_at = time.time() + ttl_seconds
            return True
        return False

    def release(self, token: LockToken) -> bool:
        lkey = self._lock_key(token.key, token.tenant_id)
        val = f"{token.owner}:{token.fencing_token}"
        res = self._release_script(keys=[lkey], args=[val])
        return bool(res)

    def is_locked(self, key: str, tenant_id: str = "default") -> bool:
        lkey = self._lock_key(key, tenant_id)
        return bool(self.redis.exists(lkey))

    def get_current_fencing_token(self, key: str, tenant_id: str = "default") -> int:
        ckey = self._counter_key(key, tenant_id)
        val = self.redis.get(ckey)
        return int(val) if val else 0
