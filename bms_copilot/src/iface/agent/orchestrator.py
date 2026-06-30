from __future__ import annotations

from typing import Protocol
from src.models.agent.schemas import (
    AgentRequest,
    AgentResponse,
    IntentResult,
    ToolCall,
    ToolResult,
)

class IIntentClassifier(Protocol):
    async def classify(self, req: AgentRequest) -> IntentResult: ...


class IPlanner(Protocol):
    async def plan(self, req: AgentRequest, intent: IntentResult) -> list[ToolCall]: ...


class IResponseSynthesizer(Protocol):
    async def synthesize(
        self,
        req: AgentRequest,
        intent: IntentResult,
        tool_results: list[ToolResult],
        retrieved_chunks: list[dict] | None = None,
    ) -> AgentResponse: ...


class IAgentOrchestrator(Protocol):
    async def run(self, req: AgentRequest) -> AgentResponse: ...
