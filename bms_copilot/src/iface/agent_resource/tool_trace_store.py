from __future__ import annotations
from typing import Any
from abc import ABC, abstractmethod


class IToolTraceStore(ABC):
    @abstractmethod
    async def save_tool_call(self, record: dict[str, Any]) -> None: ...
    @abstractmethod
    async def save_tool_result(self, record: dict[str, Any]) -> None: ...
    @abstractmethod
    async def list_tool_records(self, run_id: str) -> list[dict[str, Any]]: ...
