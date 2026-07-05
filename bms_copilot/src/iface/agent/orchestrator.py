from __future__ import annotations

from typing import Protocol
from src.models.agent.schemas import (
    AgentRequest,
    AgentResponse,
    IntentResult,
    ToolCall,
    ToolResult,
)
from src.iface.agent.knowledge import RetrievedChunk
from src.iface.agent.runtime import AgentRuntimeContext


class IIntentClassifier(Protocol):
    async def classify(
        self,
        req: AgentRequest,
        context: AgentRuntimeContext | None = None,
    ) -> IntentResult: ...


class IPlanner(Protocol):
    async def plan(
        self,
        req: AgentRequest,
        intent: IntentResult,
        context: AgentRuntimeContext | None = None,
    ) -> list[ToolCall]: ...


class IResponseSynthesizer(Protocol):
    async def synthesize(
        self,
        req: AgentRequest,
        intent: IntentResult,
        tool_results: list[ToolResult],
        retrieved_chunks: list[RetrievedChunk] | None = None,
        context: AgentRuntimeContext | None = None,
    ) -> AgentResponse: ...


class IAgentOrchestrator(Protocol):
    async def run(
        self,
        req: AgentRequest,
        context: AgentRuntimeContext | None = None,
    ) -> AgentResponse: ...
