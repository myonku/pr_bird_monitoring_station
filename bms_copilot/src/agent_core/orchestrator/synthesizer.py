import json
from typing import Any

import msgspec

from src.agent_core.common.func import conversation_handle, conversation_policy
from src.agent_core.prompot.answer import ANSWER_PROMPT
from src.models.agent.api import (
    ChatRequest,
    ProviderRequestContext,
)
from src.iface.agent.audit import IAgentAuditRecorder
from src.iface.agent.orchestrator import IResponseSynthesizer
from src.models.agent.api import ChatMessage, ChatResult
from src.iface.agent.providers import IChatProvider
from src.iface.agent.runtime import AgentRuntimeContext
from src.iface.agent_resource.usage_store import IUsageStore
from src.models.agent.audit import ProviderUsageRecord
from src.models.agent.usage import UsageRecord
from src.models.agent.schemas import (
    AgentRequest,
    AgentResponse,
    AnswerPayload,
    Citation,
    DebugTrace,
    IntentResult,
    RunStatus,
    ToolStatus,
    ToolResult,
)


class PromptResponseSynthesizer(IResponseSynthesizer):
    """基于 prompt 的回答生成器样例。

    该实现保留了 future extension 点：memory / RAG / audit 都可以通过AgentRuntimeContext 注入。
    """

    def __init__(
        self,
        provider: IChatProvider | None = None,
        *,
        model: str = "gpt-4o-mini",
        audit_recorder: IAgentAuditRecorder | None = None,
        usage_store: IUsageStore | None = None,
    ) -> None:
        self.provider = provider
        self.model = model
        self._audit_recorder = audit_recorder
        self._usage_store = usage_store

    async def synthesize(
        self,
        req: AgentRequest,
        intent: IntentResult,
        tool_results: list[ToolResult],
        retrieved_chunks: list[Any] | None = None,
        context: AgentRuntimeContext | None = None,
    ) -> AgentResponse:
        retrieved_chunks = list(
            retrieved_chunks or (context.retrieved_chunks if context else [])
        )
        answer_text = await self._compose_answer_text(
            req, intent, tool_results, retrieved_chunks, context
        )
        return AgentResponse(
            request_id=req.request_id,
            session_id=req.session_id,
            status=_derive_run_status(tool_results),
            answer=AnswerPayload(
                text=answer_text,
                structured={
                    "intent_type": (
                        intent.intent_type.value
                        if hasattr(intent.intent_type, "value")
                        else str(intent.intent_type)
                    ),
                    "tool_results": [result.model_dump() for result in tool_results],
                    "retrieved_chunks": [
                        msgspec.to_builtins(chunk) for chunk in retrieved_chunks
                    ],
                },
                cards=[],
            ),
            citations=[_chunk_to_citation(chunk) for chunk in retrieved_chunks],
            debug=DebugTrace(
                intent=(
                    intent.intent_type.value
                    if hasattr(intent.intent_type, "value")
                    else str(intent.intent_type)
                ),
                tools=[result.tool_name for result in tool_results],
                provider=getattr(self.provider, "provider_name", None),
                model=self.model,
            ),
        )

    async def _compose_answer_text(
        self,
        req: AgentRequest,
        intent: IntentResult,
        tool_results: list[ToolResult],
        retrieved_chunks: list[Any],
        context: AgentRuntimeContext | None,
    ) -> str:
        if self.provider is None:
            return _fallback_answer_text(
                req.text, intent, tool_results, retrieved_chunks
            )

        messages = [
            ChatMessage(role="system", content=ANSWER_PROMPT.render()),
            ChatMessage(
                role="user",
                content=ANSWER_PROMPT.render(
                    user_text=req.text,
                    tool_results=json.dumps(
                        [result.model_dump() for result in tool_results],
                        ensure_ascii=False,
                    ),
                    citations=json.dumps(
                        [
                            _chunk_to_citation(chunk).model_dump()
                            for chunk in retrieved_chunks
                        ],
                        ensure_ascii=False,
                    ),
                ),
            ),
        ]
        response: ChatResult = await self.provider.generate(
            ChatRequest(
                stage="answer_synthesis",
                messages=messages,
                model=self.model,
                temperature=0.2,
                max_tokens=512,
                response_format={"type": "text"},
                context=ProviderRequestContext(
                    request_id=req.request_id,
                    session_id=req.session_id,
                    user_id=req.user_id,
                    stage="answer_synthesis",
                    workflow_name="agent_core.answer",
                    prompt_name=ANSWER_PROMPT.name,
                    prompt_version=ANSWER_PROMPT.version,
                    metadata={
                        "stage": "answer_synthesis",
                        **(context.metadata if context else {}),
                    },
                ),
                conversation_policy=conversation_policy(context),
                conversation=conversation_handle(context, "answer_synthesis"),
                metadata={
                    "tool_result_count": len(tool_results),
                    "retrieved_chunk_count": len(retrieved_chunks),
                },
            ),
        )
        await self._record_usage(req, response, context)
        return response.text or _fallback_answer_text(
            req.text, intent, tool_results, retrieved_chunks
        )

    async def _record_usage(
        self,
        req: AgentRequest,
        result: ChatResult,
        context: AgentRuntimeContext | None = None,
    ) -> None:
        usage = result.usage or {}
        prompt_tokens = usage.get("input_tokens") or 0
        completion_tokens = usage.get("output_tokens") or 0
        total_tokens = prompt_tokens + completion_tokens

        # 1. 审计记录
        recorder = self._audit_recorder
        if recorder is not None:
            await recorder.usage_record(
                ProviderUsageRecord(
                    request_id=req.request_id,
                    session_id=req.session_id,
                    user_id=req.user_id,
                    provider=result.provider or "",
                    model=result.model or self.model,
                    prompt_tokens=prompt_tokens,
                    completion_tokens=completion_tokens,
                    total_tokens=total_tokens,
                )
            )

        # 2. 用量存储
        usage_store = self._usage_store
        if usage_store is not None:
            run_id = ""
            if context is not None:
                run_id = str(context.metadata.get("run_id") or "")
            await usage_store.record_usage(
                UsageRecord(
                    run_id=run_id,
                    request_id=req.request_id,
                    session_id=req.session_id,
                    user_id=req.user_id,
                    stage="answer_synthesis",
                    provider=result.provider or "",
                    model=result.model or self.model,
                    prompt_tokens=prompt_tokens,
                    completion_tokens=completion_tokens,
                    total_tokens=total_tokens,
                )
            )


def _derive_run_status(tool_results: list[ToolResult]) -> RunStatus:
    if not tool_results:
        return RunStatus.OK
    if all(result.status == ToolStatus.OK for result in tool_results):
        return RunStatus.OK
    if any(result.status == ToolStatus.OK for result in tool_results):
        return RunStatus.PARTIAL
    return RunStatus.ERROR


def _chunk_to_citation(chunk: Any) -> Citation:
    if hasattr(chunk, "model_dump"):
        chunk_data = chunk.model_dump()
    else:
        try:
            chunk_data = msgspec.to_builtins(chunk)
        except Exception:
            chunk_data = {
                "source_id": "unknown",
                "title": "unknown",
                "snippet": str(chunk),
            }
    return Citation(
        source_id=str(chunk_data.get("source_id", "unknown")),
        title=str(chunk_data.get("title", "unknown")),
        snippet=str(chunk_data.get("snippet", "")),
    )


def _fallback_answer_text(
    user_text: str,
    intent: IntentResult,
    tool_results: list[ToolResult],
    retrieved_chunks: list[Any],
) -> str:
    parts = [
        f"意图：{getattr(intent.intent_type, 'value', intent.intent_type)}",
        f"问题：{user_text}",
    ]
    if tool_results:
        parts.append("工具结果：")
        for result in tool_results:
            parts.append(
                f"- {result.tool_name}: {result.status.value if hasattr(result.status, 'value') else result.status}"
            )
    if retrieved_chunks:
        parts.append(f"引用证据数：{len(retrieved_chunks)}")
    return "\n".join(parts)
