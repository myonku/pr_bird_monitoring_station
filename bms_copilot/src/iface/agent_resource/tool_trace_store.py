from abc import abstractmethod
from typing import Protocol

from src.models.agent.tool_record import ToolCallRecord, ToolResultRecord


class IToolTraceStore(Protocol):
    @abstractmethod
    async def save_tool_call(self, record: ToolCallRecord) -> None: ...
    @abstractmethod
    async def save_tool_result(self, record: ToolResultRecord) -> None: ...
    @abstractmethod
    async def list_tool_records(
        self, run_id: str
    ) -> list[ToolCallRecord | ToolResultRecord]: ...
