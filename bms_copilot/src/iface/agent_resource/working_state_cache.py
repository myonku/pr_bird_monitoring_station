from __future__ import annotations
from typing import Any
from abc import ABC, abstractmethod


class IWorkingStateCache(ABC):
    @abstractmethod
    async def get_state(self, session_id: str) -> dict[str, Any] | None: ...
    @abstractmethod
    async def set_state(
        self, session_id: str, state: dict[str, Any], ttl_sec: int = 1800
    ) -> None: ...
    @abstractmethod
    async def clear_state(self, session_id: str) -> None: ...
