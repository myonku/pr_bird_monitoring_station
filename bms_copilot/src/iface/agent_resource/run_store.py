from __future__ import annotations
from typing import Any
from abc import ABC, abstractmethod


class IRunStore(ABC):
    @abstractmethod
    async def start_run(self, run: dict[str, Any]) -> None: ...
    @abstractmethod
    async def finish_run(
        self, run_id: str, status: str, summary: dict[str, Any]
    ) -> None: ...
    @abstractmethod
    async def get_run(self, run_id: str) -> dict[str, Any] | None: ...
