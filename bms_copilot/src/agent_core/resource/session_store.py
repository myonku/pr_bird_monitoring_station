import time
from typing import Any

from redis.asyncio import Redis

from src.iface.agent_resource.session_store import ISessionStore
from src.models.agent.session import AgentSession

_KEY_PREFIX = "bms_copilot:session"


def _sk(session_id: str) -> str:
    return f"{_KEY_PREFIX}:{session_id}"


def _now_ms() -> int:
    return int(time.time() * 1000)


_USER_KEY_PREFIX = "bms_copilot:user"


def _uk(user_id: str) -> str:
    return f"{_USER_KEY_PREFIX}:{user_id}:sessions"


class RedisSessionStore(ISessionStore):
    """基于 Redis Hash 的会话存储。

    Key: ``bms_copilot:session:{session_id}`` (Hash)
    Secondary index: ``bms_copilot:user:{user_id}:sessions`` (Sorted Set, score=updated_at_ms)
    """

    def __init__(self, redis: Redis) -> None:
        if redis is None:
            raise ValueError("redis client is required")
        self._redis = redis

    async def create_session(self, session: AgentSession) -> None:
        now = _now_ms()
        data = _session_to_hash(session, now)
        await self._redis.hset(_sk(session.session_id), mapping=data)  # type: ignore[arg-type]
        # 维护用户索引
        score = float(session.updated_at_ms or now)
        await self._redis.zadd(_uk(session.user_id), {session.session_id: score})

    async def get_session(self, session_id: str) -> AgentSession | None:
        raw: Any = await self._redis.hgetall(_sk(session_id))
        if not raw:
            return None
        return _hash_to_session(dict(raw))

    async def touch_session(self, session_id: str) -> None:
        now = _now_ms()
        await self._redis.hset(_sk(session_id), "updated_at_ms", str(now))
        # 同步更新用户索引分数
        session = await self.get_session(session_id)
        if session is not None:
            await self._redis.zadd(_uk(session.user_id), {session_id: float(now)})

    async def delete_session(self, session_id: str) -> None:
        session = await self.get_session(session_id)
        if session is not None:
            await self._redis.zrem(_uk(session.user_id), session_id)
        await self._redis.delete(_sk(session_id))

    async def list_sessions_by_user(
        self, user_id: str, limit: int = 20, offset: int = 0
    ) -> list[AgentSession]:
        """按 updated_at 降序返回用户的会话列表。"""
        session_ids = await self._redis.zrevrange(
            _uk(user_id), offset, offset + limit - 1
        )
        if not session_ids:
            return []
        results: list[AgentSession] = []
        for sid in session_ids:
            session = await self.get_session(str(sid))
            if session is not None:
                results.append(session)
        return results


def _session_to_hash(session: AgentSession, now: int) -> dict[str, str]:
    return {
        "session_id": session.session_id,
        "user_id": session.user_id,
        "provider": session.provider or "",
        "model": session.model or "",
        "status": session.status,
        "created_at_ms": str(session.created_at_ms or now),
        "updated_at_ms": str(session.updated_at_ms or now),
        "last_request_id": session.last_request_id or "",
        "last_intent_type": session.last_intent_type or "",
        "last_tool_name": session.last_tool_name or "",
        "last_tool_status": session.last_tool_status or "",
        "metadata": str(session.metadata or {}),
    }


def _hash_to_session(raw: dict[str, Any]) -> AgentSession | None:
    session_id = (raw.get("session_id") or "").strip()
    if not session_id:
        return None
    return AgentSession(
        session_id=session_id,
        user_id=str(raw.get("user_id", "")),
        provider=_empty_to_none(raw.get("provider")),
        model=_empty_to_none(raw.get("model")),
        status=raw.get("status", "active"),
        created_at_ms=_int_or_none(raw.get("created_at_ms")),
        updated_at_ms=_int_or_none(raw.get("updated_at_ms")),
        last_request_id=_empty_to_none(raw.get("last_request_id")),
        last_intent_type=_empty_to_none(raw.get("last_intent_type")),
        last_tool_name=_empty_to_none(raw.get("last_tool_name")),
        last_tool_status=_empty_to_none(raw.get("last_tool_status")),
    )


def _empty_to_none(v: Any) -> str | None:
    s = str(v or "").strip()
    return s if s else None


def _int_or_none(v: Any) -> int | None:
    if v is None:
        return None
    try:
        return int(v)
    except (ValueError, TypeError):
        return None
