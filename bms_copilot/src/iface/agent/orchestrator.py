from abc import ABC, abstractmethod
from src.models.agent.schemas import (
    AgentRequest,
    AgentResponse,
    IntentResult,
    ToolCall,
    ToolResult,
)
from src.iface.agent.knowledge import RetrievedChunk
from src.iface.agent.runtime import AgentRuntimeContext


class IIntentClassifier(ABC):
    @abstractmethod
    async def classify(
        self,
        req: AgentRequest,
        context: AgentRuntimeContext | None = None,
    ) -> IntentResult: ...


class IPlanner(ABC):
    @abstractmethod
    async def plan(
        self,
        req: AgentRequest,
        intent: IntentResult,
        context: AgentRuntimeContext | None = None,
    ) -> list[ToolCall]: ...


class IResponseSynthesizer(ABC):
    @abstractmethod
    async def synthesize(
        self,
        req: AgentRequest,
        intent: IntentResult,
        tool_results: list[ToolResult],
        retrieved_chunks: list[RetrievedChunk] | None = None,
        context: AgentRuntimeContext | None = None,
    ) -> AgentResponse: ...


class IAgentOrchestrator(ABC):
    @abstractmethod
    async def run(
        self,
        req: AgentRequest,
        context: AgentRuntimeContext | None = None,
    ) -> AgentResponse: ...
