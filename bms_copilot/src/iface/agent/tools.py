from __future__ import annotations

from typing import Protocol
from src.models.agent.schemas import AgentRequest, ToolCall, ToolResult


class ITool(Protocol):
    name: str
    description: str

    async def execute(self, call: ToolCall, req: AgentRequest) -> ToolResult: ...


class IToolRegistry(Protocol):
    def get(self, tool_name: str) -> ITool: ...

    def has(self, tool_name: str) -> bool: ...

    def list_tools(self) -> dict[str, ITool]: ...
