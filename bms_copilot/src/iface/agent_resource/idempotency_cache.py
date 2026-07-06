from abc import ABC, abstractmethod


class IIdempotencyCache(ABC):
    @abstractmethod
    async def acquire(self, key: str, ttl_sec: int = 30) -> bool: ...
    @abstractmethod
    async def release(self, key: str) -> None: ...
