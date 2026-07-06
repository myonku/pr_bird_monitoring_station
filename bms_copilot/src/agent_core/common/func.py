import json
import re
from typing import Any

from src.iface.agent.providers import ChatResult

from src.models.sys.config import AgentConfig
from src.models.agent.api import ChatRequest, ConversationPolicy
from src.iface.agent.runtime import AgentRuntimeContext


def conversation_policy(context: AgentRuntimeContext | None) -> ConversationPolicy:
    """解析 AgentRuntimeContext 中的会话策略配置。"""

    if context and context.provider_state.get("conversation_policy"):
        policy = str(context.provider_state.get("conversation_policy"))
        if policy in ("stateless", "stateful"):
            return policy
    return "stateless"


def parse_json_like(text: str | None) -> dict[str, Any] | None:
    """解析 JSON 的文本为字典。"""

    if not text:
        return None
    text = text.strip()
    if not text:
        return None
    try:
        parsed = json.loads(text)
        return parsed if isinstance(parsed, dict) else None
    except Exception:
        pass
    match = re.search(r"\{.*\}", text, flags=re.S)
    if match:
        try:
            parsed = json.loads(match.group(0))
            return parsed if isinstance(parsed, dict) else None
        except Exception:
            return None
    return None


def conversation_handle(context: AgentRuntimeContext | None, stage: str) -> Any | None:
    """解析 AgentRuntimeContext 中的会话句柄配置。"""

    if context is None:
        return None
    handle = context.provider_state.get(stage)
    if isinstance(handle, dict):
        return handle
    return None


def error_result(
    code: str,
    message: str,
    request: ChatRequest,
    config: AgentConfig,
    provider: str,
) -> ChatResult:
    """构造携带错误信息的 ChatResult，避免直接抛异常。"""
    return ChatResult(
        text="",
        raw={
            "error": {"code": code, "message": message},
            "provider_request": request.to_dict(),
        },
        usage={"input_tokens": 0, "output_tokens": 0},
        finish_reason="error",
        provider=provider,
        model=request.model or config.model,
    )
