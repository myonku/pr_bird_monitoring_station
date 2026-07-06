from abc import ABC, abstractmethod
from src.models.agent.schemas import AgentRequest, ToolCall, ToolResult


class ITool(ABC):
    name: str
    description: str

    @abstractmethod
    async def execute(self, call: ToolCall, req: AgentRequest) -> ToolResult: ...


class IToolRegistry(ABC):
    @abstractmethod
    def get(self, tool_name: str) -> ITool: ...

    @abstractmethod
    def has(self, tool_name: str) -> bool: ...

    @abstractmethod
    def list_tools(self) -> dict[str, ITool]: ...
