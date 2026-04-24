from __future__ import annotations

import json as std_json
import time
from typing import cast

from msgspec import json as msgspec_json
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

    async def save_bootstrap_credential(
        self, snapshot: ModuleCredentialSnapshot
    ) -> str:
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

        key = self._credential_key(principal_id)
        ttl_sec = self._resolve_ttl_sec(snapshot.expires_at, now)
        await self._redis.set(key, msgspec_json.encode(snapshot), ex=ttl_sec)
        return key

    async def load_active_credential(
        self, principal_id: str
    ) -> ModuleCredentialSnapshot | None:
        resolved_principal = (principal_id or "").strip()
        if not resolved_principal:
            raise ValueError("principal_id is required")

        raw = await self._redis.get(self._credential_key(resolved_principal))
        if raw is None:
            return None

        if isinstance(raw, bytes):
            raw_bytes = raw
        else:
            raw_bytes = str(raw).encode("utf-8")

        try:
            snapshot = msgspec_json.decode(raw_bytes, type=ModuleCredentialSnapshot)
        except Exception:
            payload = std_json.loads(raw_bytes.decode("utf-8"))
            metadata = payload.get("metadata")
            if not isinstance(metadata, dict):
                metadata = {}

            snapshot = ModuleCredentialSnapshot(
                principal_id=str(payload.get("principal_id", "")).strip(),
                stage=_normalize_stage(
                    str(payload.get("stage", "uninitialized")).strip()
                    or "uninitialized"
                ),
                active_comm_key_id=str(payload.get("active_comm_key_id", "")).strip(),
                issued_at=float(payload.get("issued_at", 0.0) or 0.0),
                expires_at=float(payload.get("expires_at", 0.0) or 0.0),
                updated_at=float(payload.get("updated_at", 0.0) or 0.0),
                metadata={str(k): str(v) for k, v in metadata.items()},
            )

        snapshot.principal_id = snapshot.principal_id.strip()
        snapshot.stage = _normalize_stage((snapshot.stage or "uninitialized").strip())
        snapshot.active_comm_key_id = snapshot.active_comm_key_id.strip()
        snapshot.metadata = {
            str(k): str(v) for k, v in dict(snapshot.metadata or {}).items()
        }
        return snapshot

    async def mark_credential_expired(
        self, principal_id: str, reason: str = ""
    ) -> None:
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


def is_credential_valid_for_discovery(
    snapshot: ModuleCredentialSnapshot | None,
    now: float | None = None,
) -> bool:
    if snapshot is None:
        return False

    now_ts = time.time() if now is None else now
    if not snapshot.principal_id.strip():
        return False
    if _normalize_stage((snapshot.stage or "uninitialized").strip()) != "ready":
        return False

    metadata = dict(snapshot.metadata or {})
    credential_status = (
        str(metadata.get("credential_status", "active") or "active").strip().lower()
    )
    if credential_status not in {"active", "ready"}:
        return False

    if snapshot.identity is None or snapshot.session is None or snapshot.tokens is None:
        return False
    if snapshot.tokens.access_token is None or snapshot.tokens.refresh_token is None:
        return False

    if snapshot.session.status != "active":
        return False
    if snapshot.session.expires_at > 0 and snapshot.session.expires_at <= now_ts:
        return False
    if snapshot.expires_at > 0 and snapshot.expires_at <= now_ts:
        return False
    return True


def is_credential_refresh_due(
    snapshot: ModuleCredentialSnapshot | None,
    now: float | None = None,
    refresh_leeway_sec: int = 60,
) -> bool:
    if not is_credential_valid_for_discovery(snapshot, now=now):
        return False

    now_ts = time.time() if now is None else now
    leeway = max(int(refresh_leeway_sec), 0)
    session = snapshot.session if snapshot is not None else None
    next_refresh_at = 0.0
    if session is not None and session.next_refresh_at > 0:
        next_refresh_at = session.next_refresh_at
    elif snapshot is not None and snapshot.expires_at > 0:
        next_refresh_at = snapshot.expires_at - leeway

    if next_refresh_at <= 0:
        return False
    return now_ts >= max(0.0, next_refresh_at - leeway)


def _normalize_stage(raw_stage: str) -> BootstrapStage:
    normalized = (raw_stage or "").strip().lower()
    if normalized in {"uninitialized", "challenging", "authenticating", "ready"}:
        return cast(BootstrapStage, normalized)
    return cast(BootstrapStage, "uninitialized")
