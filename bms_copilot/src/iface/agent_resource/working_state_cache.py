from __future__ import annotations

from typing import Protocol

from src.models.agent.context import SessionWorkingState


class IWorkingStateCache(Protocol):
    async def get_state(self, session_id: str) -> SessionWorkingState | None: ...

    async def set_state(
        self, state: SessionWorkingState, ttl_sec: int = 1800
    ) -> None: ...

    async def clear_state(self, session_id: str) -> None: ...
