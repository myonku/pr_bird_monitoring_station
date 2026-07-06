from abc import ABC, abstractmethod
from src.models.agent.context import SessionWorkingState


class IWorkingStateCache(ABC):
    @abstractmethod
    async def get_state(self, session_id: str) -> SessionWorkingState | None: ...

    @abstractmethod
    async def set_state(
        self, state: SessionWorkingState, ttl_sec: int = 1800
    ) -> None: ...

    @abstractmethod
    async def clear_state(self, session_id: str) -> None: ...
