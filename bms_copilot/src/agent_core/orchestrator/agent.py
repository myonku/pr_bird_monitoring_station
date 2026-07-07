import time
from dataclasses import dataclass
from typing import Any
from uuid import uuid4

import msgspec

from src.agent_core.orchestrator.executor import ToolExecutor
from src.agent_core.orchestrator.planner import PromptToolPlanner
from src.agent_core.orchestrator.router import PromptIntentClassifier
from src.agent_core.orchestrator.synthesizer import PromptResponseSynthesizer
from src.iface.agent.audit import (
    AgentAuditEvent,
    IAgentAuditRecorder,
    IAgentAuditSink,
)
from src.iface.agent.knowledge import IKnowledgeRetriever, RetrievedChunk
from src.models.agent.audit import ModelRoutingPolicy
from src.iface.agent.memory import ISessionMemory
from src.iface.agent.orchestrator import (
    IAgentOrchestrator,
    IIntentClassifier,
    IPlanner,
    IResponseSynthesizer,
)
from src.iface.agent_resource.idempotency_cache import IIdempotencyCache
from src.iface.agent_resource.run_store import IRunStore
from src.iface.agent_resource.tool_trace_store import IToolTraceStore
from src.iface.agent_resource.usage_store import IUsageStore
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
    """Agent 核心编排器样例。"""

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
        audit_recorder: IAgentAuditRecorder | None = None,
        run_store: IRunStore | None = None,
        trace_store: IToolTraceStore | None = None,
        usage_store: IUsageStore | None = None,
        idempotency_cache: IIdempotencyCache | None = None,
    ) -> None:
        self.tool_registry = tool_registry
        self.classifier = classifier or PromptIntentClassifier(
            audit_recorder=audit_recorder,
            usage_store=usage_store,
        )
        self.planner = planner or PromptToolPlanner(
            audit_recorder=audit_recorder,
            usage_store=usage_store,
        )
        self.executor = ToolExecutor(
            tool_registry,
            audit_sink=audit_sink,
            trace_store=trace_store,
        )
        self.synthesizer = synthesizer or PromptResponseSynthesizer(
            audit_recorder=audit_recorder,
            usage_store=usage_store,
        )
        self.memory = memory
        self.retriever = retriever
        self.audit_sink = audit_sink
        self._audit_recorder = audit_recorder
        self._run_store = run_store
        self._idempotency_cache = idempotency_cache

    async def run(
        self,
        req: AgentRequest,
        context: AgentRuntimeContext | None = None,
    ) -> AgentResponse:
        runtime_context = _merge_runtime_context(context)
        if not await self._acquire_idempotency(req):
            return _duplicate_response(req)
        await self._append_memory_request(req)
        await self._audit("agent_start", req, runtime_context, {"text": req.text})
        await self._record_model_policy(req)
        run_id = await self._start_run(req, runtime_context)
        if run_id:
            runtime_context.metadata["run_id"] = run_id

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
        await self._finish_run(run_id, response)
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

    async def _record_model_policy(self, req: AgentRequest) -> None:
        recorder = self._audit_recorder
        if recorder is None:
            return
        # 从第一个有 provider 的组件中提取名称
        provider_name = ""
        model_name = ""
        for comp in (self.classifier, self.planner, self.synthesizer):
            pn = getattr(comp, "provider", None)
            if pn is not None:
                provider_name = getattr(pn, "provider_name", "") or ""
                break
        for comp in (self.classifier, self.planner, self.synthesizer):
            mn = getattr(comp, "model", None)
            if mn:
                model_name = mn
                break

        await recorder.policy_record(
            ModelRoutingPolicy(
                session_id=req.session_id,
                user_id=req.user_id,
                provider=provider_name,
                model=model_name,
                policy_name="default",
            )
        )

    async def _acquire_idempotency(self, req: AgentRequest) -> bool:
        cache = self._idempotency_cache
        if cache is None:
            return True
        return await cache.acquire(req.request_id, ttl_sec=30)

    async def _start_run(
        self,
        req: AgentRequest,
        context: AgentRuntimeContext,
    ) -> str:
        store = self._run_store
        if store is None:
            return ""
        run_id = str(uuid4())
        provider_name = ""
        model_name = ""
        for comp in (self.classifier, self.planner, self.synthesizer):
            pn = getattr(comp, "provider", None)
            if pn is not None:
                provider_name = getattr(pn, "provider_name", "") or ""
                break
        for comp in (self.classifier, self.planner, self.synthesizer):
            mn = getattr(comp, "model", None)
            if mn:
                model_name = mn
                break
        now = int(time.time() * 1000)
        await store.start_run(
            {
                "run_id": run_id,
                "request_id": req.request_id,
                "session_id": req.session_id,
                "user_id": req.user_id,
                "provider": provider_name,
                "model": model_name,
                "status": "started",
                "started_at_ms": now,
            }
        )
        return run_id

    async def _finish_run(
        self,
        run_id: str,
        response: AgentResponse,
    ) -> None:
        store = self._run_store
        if store is None or not run_id:
            return
        await store.finish_run(
            run_id,
            status=(
                response.status.value
                if hasattr(response.status, "value")
                else str(response.status)
            ),
            summary={
                "answer_text": response.answer.text or "",
                "intent_type": response.debug.intent,
                "tool_names": list(response.debug.tools),
            },
        )

    async def _audit(
        self,
        event_name: str,
        req: AgentRequest,
        context: AgentRuntimeContext,
        payload: dict[str, Any],
    ) -> None:
        if self.audit_sink is None:
            return

        await self.audit_sink.record(
            AgentAuditEvent(
                event_name=event_name,
                request_id=req.request_id,
                session_id=req.session_id,
                stage="orchestration",
                payload={**payload, **context.audit_metadata},
            )
        )


def _duplicate_response(req: AgentRequest) -> AgentResponse:
    """当请求被幂等缓存拦截时返回的重复响应。"""
    from src.models.agent.schemas import AnswerPayload, DebugTrace, RunStatus

    return AgentResponse(
        request_id=req.request_id,
        session_id=req.session_id,
        status=RunStatus.OK,
        answer=AnswerPayload(
            text="(duplicate request — already processed)",
            structured={"duplicate": True},
        ),
        debug=DebugTrace(intent="unknown"),
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
