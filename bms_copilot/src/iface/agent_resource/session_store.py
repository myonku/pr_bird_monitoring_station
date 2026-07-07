from abc import ABC, abstractmethod

from src.models.agent.session import AgentSession


class ISessionStore(ABC):
    @abstractmethod
    async def create_session(self, session: AgentSession) -> None: ...

    @abstractmethod
    async def get_session(self, session_id: str) -> AgentSession | None: ...

    @abstractmethod
    async def touch_session(self, session_id: str) -> None: ...

    @abstractmethod
    async def delete_session(self, session_id: str) -> None: ...

    @abstractmethod
    async def list_sessions_by_user(
        self, user_id: str, limit: int = 20, offset: int = 0
    ) -> list[AgentSession]: ...
