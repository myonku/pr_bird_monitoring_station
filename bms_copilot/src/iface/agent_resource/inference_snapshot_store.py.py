from __future__ import annotations
from typing import Any
from abc import ABC, abstractmethod


class IInferenceSnapshotStore(ABC):
    @abstractmethod
    async def save_snapshot(self, snapshot: dict[str, Any]) -> None: ...
    @abstractmethod
    async def list_by_session(
        self, session_id: str, limit: int = 20
    ) -> list[dict[str, Any]]: ...
