from __future__ import annotations

import json
import re
from typing import Any

from src.agent_core.common.func import conversation_handle, conversation_policy, parse_json_like
from src.agent_core.prompot.intent import INTENT_PROMPT
from src.agent_core.prompot.system import SYSTEM_PROMPT
from src.models.agent.api import ChatRequest, ProviderRequestContext
from src.iface.agent.orchestrator import IIntentClassifier
from src.iface.agent.providers import ChatMessage, IChatProvider
from src.iface.agent.runtime import AgentRuntimeContext
from src.models.agent.schemas import AgentRequest, IntentResult, IntentType


class PromptIntentClassifier(IIntentClassifier):
    """基于 prompt 的意图识别样例。

    这里先保留轻量启发式 fallback，后续接真实 LLM 时只替换 provider。
    """

    def __init__(
        self,
        provider: IChatProvider | None = None,
        *,
        model: str = "gpt-4o-mini",
    ) -> None:
        self.provider = provider
        self.model = model

    async def classify(
        self,
        req: AgentRequest,
        context: AgentRuntimeContext | None = None,
    ) -> IntentResult:
        prompt_text = INTENT_PROMPT.render(user_text=req.text)
        if self.provider is not None:
            messages = self._build_messages(req, prompt_text, context)
            provider_response = await self.provider.generate(
                ChatRequest(
                    stage="intent_classification",
                    messages=messages,
                    model=self.model,
                    temperature=0.0,
                    max_tokens=256,
                    response_format={"type": "json_object"},
                    context=ProviderRequestContext(
                        request_id=req.request_id,
                        session_id=req.session_id,
                        user_id=req.user_id,
                        stage="intent_classification",
                        workflow_name="agent_core.intent",
                        prompt_name=INTENT_PROMPT.name,
                        prompt_version=INTENT_PROMPT.version,
                        metadata={"stage": "intent_classification"},
                    ),
                    conversation_policy=conversation_policy(context),
                    conversation=conversation_handle(context, "intent_classification"),
                    metadata={"prompt": prompt_text},
                )
            )
            parsed = parse_json_like(provider_response.text) or parse_json_like(
                _extract_raw_text(provider_response.raw)
            )
            if isinstance(parsed, dict):
                return _intent_from_payload(parsed, req.text)

        return _heuristic_intent(req.text, req.images, context)

    def _build_messages(
        self,
        req: AgentRequest,
        prompt_text: str,
        context: AgentRuntimeContext | None,
    ) -> list[ChatMessage]:
        messages: list[ChatMessage] = [
            ChatMessage(role="system", content=SYSTEM_PROMPT.render()),
            ChatMessage(role="user", content=prompt_text),
        ]
        if context and context.recent_messages:
            messages.extend(context.recent_messages)
        return messages

def _heuristic_intent(
    text: str, images: list[Any], context: AgentRuntimeContext | None
) -> IntentResult:
    normalized = text.lower().strip()
    has_image = len(images) > 0
    if any(
        keyword in normalized for keyword in ["统计", "趋势", "count", "top", "分布"]
    ):
        intent_type = IntentType.STATISTICS
    elif (
        any(
            keyword in normalized
            for keyword in ["识别", "图片", "图像", "检测", "分类"]
        )
        or has_image
    ):
        intent_type = IntentType.INFERENCE
    elif any(
        keyword in normalized for keyword in ["知识", "百科", "说明", "是什么", "介绍"]
    ):
        intent_type = IntentType.KNOWLEDGE
    elif any(
        keyword in normalized for keyword in ["和", "以及", "同时", "综合", "组合"]
    ):
        intent_type = IntentType.COMPOSITE
    elif normalized:
        intent_type = IntentType.SEARCH
    else:
        intent_type = IntentType.UNKNOWN

    slots = {
        "query": text,
        "has_image": has_image,
        "history_messages": len(context.recent_messages) if context else 0,
    }
    return IntentResult(
        intent_type=intent_type,
        confidence=0.55 if intent_type != IntentType.UNKNOWN else 0.2,
        slots=slots,
        need_rag=intent_type in {IntentType.KNOWLEDGE, IntentType.COMPOSITE},
        tool_plan_hint=_tool_hints_for_intent(intent_type),
    )


def _intent_from_payload(payload: dict[str, Any], raw_text: str) -> IntentResult:
    intent_value = str(
        payload.get("intent_type") or payload.get("intent") or "unknown"
    ).lower()
    intent_map = {
        "search": IntentType.SEARCH,
        "statistics": IntentType.STATISTICS,
        "inference": IntentType.INFERENCE,
        "knowledge": IntentType.KNOWLEDGE,
        "composite": IntentType.COMPOSITE,
        "unknown": IntentType.UNKNOWN,
    }
    intent_type = intent_map.get(intent_value, IntentType.UNKNOWN)
    slots = payload.get("slots") if isinstance(payload.get("slots"), dict) else {}
    if not isinstance(slots, dict):
        slots = {}
    slots.setdefault("query", raw_text)
    return IntentResult(
        intent_type=intent_type,
        confidence=float(payload.get("confidence") or 0.0),
        slots=slots,
        need_rag=bool(
            payload.get("need_rag")
            or intent_type in {IntentType.KNOWLEDGE, IntentType.COMPOSITE}
        ),
        tool_plan_hint=list(
            payload.get("tool_plan_hint") or _tool_hints_for_intent(intent_type)
        ),
    )


def _tool_hints_for_intent(intent_type: IntentType) -> list[str]:
    if intent_type == IntentType.SEARCH:
        return ["search_records_tool"]
    if intent_type == IntentType.STATISTICS:
        return ["stats_query_tool"]
    if intent_type == IntentType.INFERENCE:
        return ["image_inference_tool"]
    if intent_type == IntentType.KNOWLEDGE:
        return ["species_kb_tool"]
    if intent_type == IntentType.COMPOSITE:
        return ["search_records_tool", "species_kb_tool"]
    return []


def _extract_raw_text(raw: Any | None) -> str | None:
    if raw is None:
        return None
    if isinstance(raw, str):
        return raw
    if isinstance(raw, dict):
        for key in ("text", "content", "output"):
            value = raw.get(key)
            if isinstance(value, str):
                return value
    return None
