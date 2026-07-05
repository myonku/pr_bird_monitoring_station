from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import msgspec

from src.agent_core.orchestrator.executor import ToolExecutor
from src.agent_core.orchestrator.planner import PromptToolPlanner
from src.agent_core.orchestrator.router import PromptIntentClassifier
from src.agent_core.orchestrator.synthesizer import PromptResponseSynthesizer
from src.iface.agent.audit import IAgentAuditSink
from src.iface.agent.knowledge import IKnowledgeRetriever, RetrievedChunk
from src.iface.agent.memory import ISessionMemory
from src.iface.agent.orchestrator import (
    IAgentOrchestrator,
    IIntentClassifier,
    IPlanner,
    IResponseSynthesizer,
)
from src.iface.agent.runtime import AgentRuntimeContext
from src.iface.agent.tools import IToolRegistry
from src.models.agent.schemas import (
    AgentRequest,
    AgentResponse,
    IntentResult,
    ToolCall,
    ToolResult,
)


@dataclass(slots=True)
class AgentComponentBundle:
    classifier: IIntentClassifier
    planner: IPlanner
    executor: ToolExecutor
    synthesizer: IResponseSynthesizer


class AgentOrchestrator(IAgentOrchestrator):
    """Agent 核心编排器样例。

    未来扩展 memory / RAG / audit 时，只需要把依赖注入进来，主流程不必重写。
    """

    def __init__(
        self,
        tool_registry: IToolRegistry,
        *,
        classifier: IIntentClassifier | None = None,
        planner: IPlanner | None = None,
        synthesizer: IResponseSynthesizer | None = None,
        memory: ISessionMemory | None = None,
        retriever: IKnowledgeRetriever | None = None,
        audit_sink: IAgentAuditSink | None = None,
    ) -> None:
        self.tool_registry = tool_registry
        self.classifier = classifier or PromptIntentClassifier()
        self.planner = planner or PromptToolPlanner()
        self.executor = ToolExecutor(tool_registry, audit_sink=audit_sink)
        self.synthesizer = synthesizer or PromptResponseSynthesizer()
        self.memory = memory
        self.retriever = retriever
        self.audit_sink = audit_sink

    async def run(
        self,
        req: AgentRequest,
        context: AgentRuntimeContext | None = None,
    ) -> AgentResponse:
        runtime_context = _merge_runtime_context(context)
        await self._append_memory_request(req)
        await self._audit("agent_start", req, runtime_context, {"text": req.text})

        if self.memory is not None:
            recent_messages = await self.memory.get_recent_messages(req.session_id)
            runtime_context.recent_messages = list(recent_messages)

        intent = await self.classifier.classify(req, runtime_context)
        await self._append_intent(req, intent)
        await self._audit(
            "intent_classified", req, runtime_context, intent.model_dump()
        )

        if self._should_retrieve(intent, runtime_context):
            retrieved_chunks = await self._retrieve_knowledge(
                req, intent, runtime_context
            )
            runtime_context.retrieved_chunks = retrieved_chunks
            await self._audit(
                "knowledge_retrieved",
                req,
                runtime_context,
                {
                    "count": len(retrieved_chunks),
                    "chunks": [
                        msgspec.to_builtins(chunk) for chunk in retrieved_chunks
                    ],
                },
            )

        tool_calls = await self.planner.plan(req, intent, runtime_context)
        await self._append_tool_calls(req, tool_calls)
        await self._audit(
            "plan_built",
            req,
            runtime_context,
            {"tool_calls": [call.model_dump() for call in tool_calls]},
        )

        tool_results = await self.executor.execute(req, tool_calls, runtime_context)
        await self._append_tool_results(req, tool_results)

        response = await self.synthesizer.synthesize(
            req,
            intent,
            tool_results,
            retrieved_chunks=runtime_context.retrieved_chunks,
            context=runtime_context,
        )
        await self._append_response(response)
        await self._audit("agent_finish", req, runtime_context, response.model_dump())
        return response

    def build_default_components(self) -> AgentComponentBundle:
        return AgentComponentBundle(
            classifier=self.classifier,
            planner=self.planner,
            executor=self.executor,
            synthesizer=self.synthesizer,
        )

    async def _retrieve_knowledge(
        self,
        req: AgentRequest,
        intent: IntentResult,
        context: AgentRuntimeContext,
    ) -> list[RetrievedChunk]:
        if self.retriever is None:
            return []
        query = context.metadata.get("rag_query") or req.text
        top_k = int(context.metadata.get("rag_top_k") or 5)
        filters = (
            context.metadata.get("rag_filters")
            if isinstance(context.metadata.get("rag_filters"), dict)
            else None
        )
        return await self.retriever.retrieve(query, top_k=top_k, filters=filters)

    def _should_retrieve(
        self, intent: IntentResult, context: AgentRuntimeContext
    ) -> bool:
        if self.retriever is None:
            return False
        if context.metadata.get("enable_rag") is True:
            return True
        return bool(intent.need_rag)

    async def _append_memory_request(self, req: AgentRequest) -> None:
        if self.memory is not None:
            await self.memory.append_user_request(req)

    async def _append_intent(self, req: AgentRequest, intent: IntentResult) -> None:
        if self.memory is not None:
            await self.memory.append_intent(req.session_id, intent)

    async def _append_tool_calls(
        self, req: AgentRequest, tool_calls: list[ToolCall]
    ) -> None:
        if self.memory is None:
            return
        for call in tool_calls:
            await self.memory.append_tool_call(req.session_id, call)

    async def _append_tool_results(
        self, req: AgentRequest, tool_results: list[ToolResult]
    ) -> None:
        if self.memory is None:
            return
        for result in tool_results:
            await self.memory.append_tool_result(req.session_id, result)

    async def _append_response(self, response: AgentResponse) -> None:
        if self.memory is not None:
            await self.memory.append_assistant_response(response)

    async def _audit(
        self,
        event_name: str,
        req: AgentRequest,
        context: AgentRuntimeContext,
        payload: dict[str, Any],
    ) -> None:
        if self.audit_sink is None:
            return
        from src.iface.agent.audit import AgentAuditEvent

        await self.audit_sink.record(
            AgentAuditEvent(
                event_name=event_name,
                request_id=req.request_id,
                session_id=req.session_id,
                stage="orchestration",
                payload={**payload, **context.audit_metadata},
            )
        )


def _merge_runtime_context(context: AgentRuntimeContext | None) -> AgentRuntimeContext:
    if context is None:
        return AgentRuntimeContext()
    return AgentRuntimeContext(
        recent_messages=list(context.recent_messages),
        retrieved_chunks=list(context.retrieved_chunks),
        metadata=dict(context.metadata),
        session_state=dict(context.session_state),
        audit_metadata=dict(context.audit_metadata),
    )
