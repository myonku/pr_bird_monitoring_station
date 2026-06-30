from __future__ import annotations

from typing import Protocol
from .providers import ChatMessage
from src.models.agent.schemas import AgentRequest, AgentResponse, IntentResult, ToolCall, ToolResult


class ISessionMemory(Protocol):
    async def get_recent_messages(
        self, session_id: str, limit: int = 20
    ) -> list[ChatMessage]: ...

    async def append_user_request(self, req: AgentRequest) -> None: ...

    async def append_assistant_response(self, res: AgentResponse) -> None: ...

    async def append_intent(self, session_id: str, intent: IntentResult) -> None: ...

    async def append_tool_call(self, session_id: str, call: ToolCall) -> None: ...

    async def append_tool_result(self, session_id: str, result: ToolResult) -> None: ...
