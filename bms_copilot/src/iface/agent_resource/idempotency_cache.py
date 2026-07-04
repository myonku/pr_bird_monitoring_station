from __future__ import annotations

from typing import Protocol


class IIdempotencyCache(Protocol):
    async def acquire(self, key: str, ttl_sec: int = 30) -> bool: ...

    async def release(self, key: str) -> None: ...
