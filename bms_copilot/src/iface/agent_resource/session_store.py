from __future__ import annotations

from typing import Protocol

from src.models.agent.session import AgentSession


class ISessionStore(Protocol):
    async def create_session(self, session: AgentSession) -> None: ...

    async def get_session(self, session_id: str) -> AgentSession | None: ...

    async def touch_session(self, session_id: str) -> None: ...

    async def delete_session(self, session_id: str) -> None: ...
