from __future__ import annotations

import json
import time

from redis.asyncio import Redis
from redis.asyncio.cluster import RedisCluster

from src.iface.common.local_credential_manager import (
    ILocalCredentialManager,
    ModuleCredentialSnapshot,
    BootstrapStage,
)


DEFAULT_LOCAL_CREDENTIAL_KEY_PREFIX = "bms/local_credentials"
DEFAULT_LOCAL_CREDENTIAL_TTL_SEC = 24 * 60 * 60


class LocalCredentialService(ILocalCredentialManager):
    def __init__(
        self,
        redis_client: Redis | RedisCluster,
        key_prefix: str = DEFAULT_LOCAL_CREDENTIAL_KEY_PREFIX,
        default_ttl_sec: int = DEFAULT_LOCAL_CREDENTIAL_TTL_SEC,
    ) -> None:
        if redis_client is None:
            raise ValueError("redis client is required")
        self._redis = redis_client
        resolved_prefix = (key_prefix or "").strip().strip("/")
        self._key_prefix = resolved_prefix or DEFAULT_LOCAL_CREDENTIAL_KEY_PREFIX
        self._default_ttl_sec = max(int(default_ttl_sec), 1)

    async def save_bootstrap_credential(self, snapshot: ModuleCredentialSnapshot) -> str:
        if snapshot is None:
            raise ValueError("bootstrap credential snapshot is required")

        principal_id = (snapshot.principal_id or "").strip()
        if not principal_id:
            raise ValueError("principal_id is required")

        now = time.time()
        if not snapshot.stage:
            snapshot.stage = "ready"
        if snapshot.issued_at <= 0:
            snapshot.issued_at = now
        if snapshot.expires_at <= 0:
            snapshot.expires_at = now + 900
        snapshot.updated_at = now
        snapshot.metadata = dict(snapshot.metadata or {})

        payload = {
            "principal_id": principal_id,
            "stage": snapshot.stage,
            "active_comm_key_id": snapshot.active_comm_key_id,
            "issued_at": snapshot.issued_at,
            "expires_at": snapshot.expires_at,
            "updated_at": snapshot.updated_at,
            "metadata": snapshot.metadata,
        }

        key = self._credential_key(principal_id)
        ttl_sec = self._resolve_ttl_sec(snapshot.expires_at, now)
        await self._redis.set(key, json.dumps(payload, ensure_ascii=True), ex=ttl_sec)
        return key

    async def load_active_credential(self, principal_id: str) -> ModuleCredentialSnapshot | None:
        resolved_principal = (principal_id or "").strip()
        if not resolved_principal:
            raise ValueError("principal_id is required")

        raw = await self._redis.get(self._credential_key(resolved_principal))
        if raw is None:
            return None

        if isinstance(raw, bytes):
            raw = raw.decode("utf-8")
        payload = json.loads(raw)
        metadata = payload.get("metadata")
        if not isinstance(metadata, dict):
            metadata = {}

        get_stage = lambda s: s if s in BootstrapStage else "uninitialized"
        
        return ModuleCredentialSnapshot(
            principal_id=str(payload.get("principal_id", "")).strip(),
            stage=get_stage(str(payload.get("stage", "uninitialized")).strip() or "uninitialized"),
            active_comm_key_id=str(payload.get("active_comm_key_id", "")).strip(),
            issued_at=float(payload.get("issued_at", 0.0) or 0.0),
            expires_at=float(payload.get("expires_at", 0.0) or 0.0),
            updated_at=float(payload.get("updated_at", 0.0) or 0.0),
            metadata={str(k): str(v) for k, v in metadata.items()},
        )

    async def mark_credential_expired(self, principal_id: str, reason: str = "") -> None:
        snapshot = await self.load_active_credential(principal_id)
        if snapshot is None:
            return

        snapshot.stage = "uninitialized"
        snapshot.updated_at = time.time()
        snapshot.metadata = dict(snapshot.metadata or {})
        snapshot.metadata["credential_status"] = "expired"
        snapshot.metadata["credential_reason"] = (reason or "").strip()
        await self.save_bootstrap_credential(snapshot)

    async def revoke_credential(self, principal_id: str, reason: str = "") -> None:
        resolved_principal = (principal_id or "").strip()
        if not resolved_principal:
            raise ValueError("principal_id is required")
        _ = reason
        await self._redis.delete(self._credential_key(resolved_principal))

    def _credential_key(self, principal_id: str) -> str:
        return f"/{self._key_prefix}/{principal_id.strip()}"

    def _resolve_ttl_sec(self, expires_at: float, now: float) -> int:
        if expires_at > now:
            return max(int(expires_at - now), 1)
        return self._default_ttl_sec
