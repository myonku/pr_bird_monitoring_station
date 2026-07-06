import json
from typing import Any

from redis.asyncio import Redis

from src.iface.agent_resource.turn_store import ITurnStore

_KEY_PREFIX = "bms_copilot:session"


def _tk(session_id: str) -> str:
    return f"{_KEY_PREFIX}:{session_id}:turns"


class RedisTurnStore(ITurnStore):
    """基于 Redis List 的轮次存储。

    Key: ``bms_copilot:session:{session_id}:turns``
    每个元素为 JSON 编码的 turn dict。
    """

    def __init__(self, redis: Redis) -> None:
        if redis is None:
            raise ValueError("redis client is required")
        self._redis = redis

    async def append_turn(self, session_id: str, turn: dict[str, Any]) -> None:
        encoded = json.dumps(turn, ensure_ascii=False, default=str)
        await self._redis.rpush(_tk(session_id), encoded)  # type: ignore[arg-type]

    async def list_recent_turns(
        self, session_id: str, limit: int = 20
    ) -> list[dict[str, Any]]:
        raw_list = await self._redis.lrange(_tk(session_id), -limit, -1)
        result: list[dict[str, Any]] = []
        for item in raw_list:
            if isinstance(item, (str, bytes)):
                try:
                    parsed = json.loads(item)
                    if isinstance(parsed, dict):
                        result.append(parsed)
                except (json.JSONDecodeError, TypeError):
                    continue
        return result
