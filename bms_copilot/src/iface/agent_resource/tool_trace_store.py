from __future__ import annotations

from typing import Protocol

from src.models.agent.session import ToolCallRecord, ToolResultRecord


class IToolTraceStore(Protocol):
    async def save_tool_call(self, record: ToolCallRecord) -> None: ...

    async def save_tool_result(self, record: ToolResultRecord) -> None: ...

    async def list_tool_records(
        self, run_id: str
    ) -> list[ToolCallRecord | ToolResultRecord]: ...
