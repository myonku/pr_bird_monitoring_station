from typing import Any

from src.agent_core.common.func import (
    conversation_handle,
    conversation_policy,
    parse_json_like,
)
from src.agent_core.prompot.tool_router import TOOL_ROUTER_PROMPT
from src.models.agent.api import ChatRequest, ProviderRequestContext
from src.iface.agent.audit import IAgentAuditRecorder
from src.iface.agent.orchestrator import IPlanner
from src.models.agent.api import ChatMessage, ChatResult
from src.iface.agent.providers import IChatProvider
from src.iface.agent.runtime import AgentRuntimeContext
from src.iface.agent_resource.usage_store import IUsageStore
from src.models.agent.audit import ProviderUsageRecord
from src.models.agent.schemas import AgentRequest, IntentResult, ToolCall, IntentType
from src.models.agent.usage import UsageRecord


class PromptToolPlanner(IPlanner):
    """基于 prompt 的工具规划器样例。

    可通过 tool_catalog 增减工具，不把具体业务逻辑写死在这里。
    """

    def __init__(
        self,
        provider: IChatProvider | None = None,
        *,
        model: str = "gpt-4o-mini",
        tool_catalog: dict[str, str] | None = None,
        audit_recorder: IAgentAuditRecorder | None = None,
        usage_store: IUsageStore | None = None,
    ) -> None:
        self.provider = provider
        self.model = model
        self._audit_recorder = audit_recorder
        self._usage_store = usage_store
        self.tool_catalog = tool_catalog or {
            "query_records_tool": "数据查询（监测记录、设备信息、鸟种简介、统计聚合）",
            "image_inference_tool": "图片识别编排",
        }

    async def plan(
        self,
        req: AgentRequest,
        intent: IntentResult,
        context: AgentRuntimeContext | None = None,
    ) -> list[ToolCall]:
        if self.provider is not None:
            context_data: dict[str, Any] = {
                "session_id": req.session_id,
                "history_messages": (len(context.recent_messages) if context else 0),
                "retrieved_chunks": (len(context.retrieved_chunks) if context else 0),
                "metadata": context.metadata if context else {},
            }
            schema_text = ""
            if intent.intent_type in IntentType:
                from src.modules.query.schema import build_schema_prompt

                schema_text = build_schema_prompt()

            messages = [
                ChatMessage(role="system", content=TOOL_ROUTER_PROMPT.render()),
                ChatMessage(
                    role="user",
                    content=TOOL_ROUTER_PROMPT.render(
                        intent=intent.model_dump(),
                        context=context_data,
                        available_tools=self.tool_catalog,
                        schema=schema_text,
                    ),
                ),
            ]
            provider_response = await self.provider.generate(
                ChatRequest(
                    stage="tool_planning",
                    messages=messages,
                    model=self.model,
                    temperature=0.0,
                    max_tokens=256,
                    response_format={"type": "json_object"},
                    context=ProviderRequestContext(
                        request_id=req.request_id,
                        session_id=req.session_id,
                        user_id=req.user_id,
                        stage="tool_planning",
                        workflow_name="agent_core.tool_router",
                        prompt_name=TOOL_ROUTER_PROMPT.name,
                        prompt_version=TOOL_ROUTER_PROMPT.version,
                        metadata={"stage": "tool_planning"},
                    ),
                    conversation_policy=conversation_policy(context),
                    conversation=conversation_handle(context, "tool_planning"),
                    metadata={"intent": intent.model_dump()},
                ),
            )
            await self._record_usage(req, provider_response, context)
            parsed = parse_json_like(provider_response.text)
            if isinstance(parsed, dict):
                tools = parsed.get("tools")
                if isinstance(tools, list):
                    return [
                        _tool_call_from_payload(item)
                        for item in tools
                        if isinstance(item, dict)
                    ]

        return _fallback_plan(req, intent, context)

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

        # 审计记录
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

        # 用量存储
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
                    stage="tool_planning",
                    provider=result.provider or "",
                    model=result.model or self.model,
                    prompt_tokens=prompt_tokens,
                    completion_tokens=completion_tokens,
                    total_tokens=total_tokens,
                )
            )


def _fallback_plan(
    req: AgentRequest,
    intent: IntentResult,
    context: AgentRuntimeContext | None,
) -> list[ToolCall]:
    hints = list(intent.tool_plan_hint)
    if not hints:
        hints = _tool_hints_for_intent(intent.intent_type)
    if intent.intent_type == IntentType.COMPOSITE and len(hints) < 2:
        hints = ["query_records_tool", "image_inference_tool"]

    plan: list[ToolCall] = []
    seen: set[str] = set()
    for tool_name in hints:
        if tool_name in seen:
            continue
        if tool_name not in {
            "query_records_tool",
            "image_inference_tool",
        }:
            continue
        seen.add(tool_name)
        plan.append(
            ToolCall(
                tool_name=tool_name,
                arguments=_default_tool_arguments(tool_name, req, intent, context),
                timeout_ms=_timeout_for_tool(tool_name),
            )
        )

    if not plan and intent.intent_type != IntentType.UNKNOWN:
        tool_name = (
            _tool_hints_for_intent(intent.intent_type)[0]
            if _tool_hints_for_intent(intent.intent_type)
            else "query_records_tool"
        )
        plan.append(
            ToolCall(
                tool_name=tool_name,
                arguments=_default_tool_arguments(tool_name, req, intent, context),
                timeout_ms=_timeout_for_tool(tool_name),
            )
        )
    return plan


def _tool_hints_for_intent(intent_type: IntentType) -> list[str]:
    if intent_type in {IntentType.SEARCH, IntentType.STATISTICS, IntentType.KNOWLEDGE}:
        return ["query_records_tool"]
    if intent_type == IntentType.INFERENCE:
        return ["image_inference_tool"]
    if intent_type == IntentType.COMPOSITE:
        return ["query_records_tool", "image_inference_tool"]
    return []


def _default_tool_arguments(
    tool_name: str,
    req: AgentRequest,
    intent: IntentResult,
    context: AgentRuntimeContext | None,
) -> dict[str, Any]:
    return {
        "request_id": req.request_id,
        "session_id": req.session_id,
        "user_id": req.user_id,
        "query": req.text,
        "intent_type": (
            intent.intent_type.value
            if hasattr(intent.intent_type, "value")
            else str(intent.intent_type)
        ),
        "metadata": context.metadata if context else {},
    }


def _timeout_for_tool(tool_name: str) -> int:
    return {
        "query_records_tool": 10000,
        "image_inference_tool": 8000,
    }.get(tool_name, 10000)


def _tool_call_from_payload(payload: dict[str, Any]) -> ToolCall:
    args = payload.get("arguments")
    if not isinstance(args, dict):
        args = {}
    return ToolCall(
        tool_name=str(payload.get("tool_name") or payload.get("name") or ""),
        arguments=args,
        timeout_ms=int(payload.get("timeout_ms") or 3000),
    )
