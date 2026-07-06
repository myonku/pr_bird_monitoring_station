from redis.asyncio import Redis
from src.iface.agent_resource.idempotency_cache import IIdempotencyCache

_KEY_PREFIX = "bms_copilot:idempotency"


def _ik(key: str) -> str:
    return f"{_KEY_PREFIX}:{key}"


class RedisIdempotencyCache(IIdempotencyCache):
    """基于 Redis SET NX EX 的幂等缓存。

    每个 key 在 TTL 内只能被 acquire 一次。
    """

    def __init__(self, redis: Redis) -> None:
        if redis is None:
            raise ValueError("redis client is required")
        self._redis = redis

    async def acquire(self, key: str, ttl_sec: int = 30) -> bool:
        result = await self._redis.set(_ik(key), "1", nx=True, ex=ttl_sec)
        return result is not None

    async def release(self, key: str) -> None:
        await self._redis.delete(_ik(key))
