from __future__ import annotations
from typing import Any
from abc import ABC, abstractmethod


class ISessionStore(ABC):
    @abstractmethod
    async def create_session(
        self, session_id: str, user_id: str, meta: dict[str, Any]
    ) -> None: ...
    async def get_session(self, session_id: str) -> dict[str, Any] | None: ...
    async def touch_session(self, session_id: str) -> None: ...
