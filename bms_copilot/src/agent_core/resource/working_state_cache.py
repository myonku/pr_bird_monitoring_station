import json
import time

import msgspec
from redis.asyncio import Redis

from src.iface.agent_resource.working_state_cache import IWorkingStateCache
from src.models.agent.context import SessionWorkingState

_KEY_PREFIX = "bms_copilot:session"


def _wk(session_id: str) -> str:
    return f"{_KEY_PREFIX}:{session_id}:state"


def _now_ms() -> int:
    return int(time.time() * 1000)


class RedisWorkingStateCache(IWorkingStateCache):
    """基于 Redis String（带 TTL）的工作状态缓存。

    Key: ``bms_copilot:session:{session_id}:state``
    Value: JSON 编码的 ``SessionWorkingState``。
    默认 TTL 30 分钟，适用于会话级中间状态。
    """

    def __init__(self, redis: Redis) -> None:
        if redis is None:
            raise ValueError("redis client is required")
        self._redis = redis

    async def get_state(self, session_id: str) -> SessionWorkingState | None:
        raw = await self._redis.get(_wk(session_id))
        if not raw:
            return None
        try:
            data = json.loads(raw)
            return msgspec.convert(data, SessionWorkingState)
        except (json.JSONDecodeError, msgspec.ValidationError, TypeError):
            return None

    async def set_state(self, state: SessionWorkingState, ttl_sec: int = 1800) -> None:
        raw = msgspec.to_builtins(state)
        encoded = json.dumps(raw, ensure_ascii=False, default=str)
        await self._redis.setex(_wk(state.session_id), ttl_sec, encoded)

    async def clear_state(self, session_id: str) -> None:
        await self._redis.delete(_wk(session_id))
