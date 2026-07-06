from abc import abstractmethod
from typing import Protocol


class IIdempotencyCache(Protocol):
    @abstractmethod
    async def acquire(self, key: str, ttl_sec: int = 30) -> bool: ...
    @abstractmethod
    async def release(self, key: str) -> None: ...
