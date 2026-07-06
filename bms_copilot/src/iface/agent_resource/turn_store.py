from typing import Any
from abc import ABC, abstractmethod


class ITurnStore(ABC):
    @abstractmethod
    async def append_turn(self, session_id: str, turn: dict[str, Any]) -> None: ...
    @abstractmethod
    async def list_recent_turns(
        self, session_id: str, limit: int = 20
    ) -> list[dict[str, Any]]: ...
