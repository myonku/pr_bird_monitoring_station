from __future__ import annotations

from time import time
from uuid import UUID

from msgspec import json as msgjson

from src.models.auth.auth import Session, SessionTouchMeta
from src.models.auth.auth_contract import SessionValidateRequest
from src.repo.redis_store import RedisManager


class SessionService:
    """会话读取、更新和状态校验服务。"""

    def __init__(self, redis_manager: RedisManager | None = None):
        self._sessions: dict[UUID, Session] = {}
        self._redis_manager = redis_manager

    def _session_key(self, sid: UUID) -> str:
        return f"auth:session:id:{sid}"

    async def _cache_session(self, session: Session) -> None:
        if self._redis_manager is None:
            return
        redis = self._redis_manager.get_client()
        ttl = max(int(session.expires_at - time()), 5)
        await redis.set(self._session_key(session.id), msgjson.encode(session), ex=ttl)

    async def _load_cached_session(self, sid: UUID) -> Session | None:
        if self._redis_manager is None:
            return None
        redis = self._redis_manager.get_client()
        raw = await redis.get(self._session_key(sid))
        if not raw:
            return None
        if isinstance(raw, str):
            raw = raw.encode("utf-8")
        return msgjson.decode(raw, type=Session)

    def upsert_session(self, session: Session | None) -> None:
        if session is None:
            return
        self._sessions[session.id] = session

    async def upsert_session_async(self, session: Session | None) -> None:
        if session is None:
            return
        self._sessions[session.id] = session
        await self._cache_session(session)

    async def get_session(self, session_id: str) -> Session | None:
        try:
            sid = UUID(session_id)
        except ValueError:
            return None
        session = self._sessions.get(sid)
        if session is not None:
            return session
        cached = await self._load_cached_session(sid)
        if cached is not None:
            self._sessions[sid] = cached
        return cached

    async def touch_session(self, session_id: str, meta: SessionTouchMeta) -> None:
        session = await self.get_session(session_id)
        if session is None or session.status != "active":
            return
        now = time()
        self._sessions[session.id] = Session(
            id=session.id,
            principal=session.principal,
            entity_type=session.entity_type,
            entity_id=session.entity_id,
            principal_id=session.principal_id,
            status=session.status,
            auth_method=session.auth_method,
            created_by_ip=session.created_by_ip,
            last_seen_ip=meta.source_ip or session.last_seen_ip,
            user_agent=meta.user_agent or session.user_agent,
            client_id=meta.client_id or session.client_id,
            gateway_id=meta.gateway_id or session.gateway_id,
            scope_snapshot=list(session.scope_snapshot),
            role_snapshot=session.role_snapshot,
            token_family_id=session.token_family_id,
            created_at=session.created_at,
            updated_at=now,
            last_seen_at=now,
            last_verified_at=session.last_verified_at,
            next_refresh_at=session.next_refresh_at,
            expires_at=session.expires_at,
            revoked_at=session.revoked_at,
            version=session.version + 1,
        )
        await self._cache_session(self._sessions[session.id])

    async def validate_session(self, req: SessionValidateRequest) -> Session | None:
        session = self._sessions.get(req.session_id)
        if session is None:
            return None
        if req.principal_id and req.principal_id != session.principal_id:
            return None
        if req.require_active and session.status != "active":
            return None
        if req.min_version > 0 and session.version < req.min_version:
            return None
        if session.expires_at > 0 and time() > session.expires_at:
            return None
        await self._cache_session(session)
        return session
