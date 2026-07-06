from abc import ABC, abstractmethod
from src.models.agent.api import ChatMessage
from src.models.agent.schemas import (
    AgentRequest,
    AgentResponse,
    IntentResult,
    ToolCall,
    ToolResult,
)


class ISessionMemory(ABC):
    """会话记忆接口。"""

    @abstractmethod
    async def get_recent_messages(
        self, session_id: str, limit: int = 20
    ) -> list[ChatMessage]: ...

    @abstractmethod
    async def append_user_request(self, req: AgentRequest) -> None: ...

    @abstractmethod
    async def append_assistant_response(self, res: AgentResponse) -> None: ...

    @abstractmethod
    async def append_intent(self, session_id: str, intent: IntentResult) -> None: ...

    @abstractmethod
    async def append_tool_call(self, session_id: str, call: ToolCall) -> None: ...

    @abstractmethod
    async def append_tool_result(self, session_id: str, result: ToolResult) -> None: ...
