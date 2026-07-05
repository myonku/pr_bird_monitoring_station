from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

import msgspec

ProviderStage = Literal[
    "system",
    "intent",
    "tool_router",
    "answer",
    "answer_synthesis",
    "embedding",
    "other",
    "intent_classification",
    "tool_planning",
]
ConversationPolicy = Literal["stateless", "stateful"]


@dataclass(slots=True, kw_only=True)
class ProviderRequestContext:
    """统一的 provider 请求上下文样例。"""

    request_id: str = ""
    session_id: str = ""
    user_id: str = ""
    trace_id: str = ""
    stage: ProviderStage = "other"
    workflow_name: str = ""
    turn_index: int | None = None
    prompt_name: str = ""
    prompt_version: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "request_id": self.request_id,
            "session_id": self.session_id,
            "user_id": self.user_id,
            "trace_id": self.trace_id,
            "stage": self.stage,
            "workflow_name": self.workflow_name,
            "turn_index": self.turn_index,
            "prompt_name": self.prompt_name,
            "prompt_version": self.prompt_version,
            "metadata": dict(self.metadata),
        }


@dataclass(slots=True, kw_only=True)
class ProviderConversationHandle:
    """可选的供应商会话句柄。"""

    provider_conversation_id: str = ""
    provider_thread_id: str = ""
    provider_session_id: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "provider_conversation_id": self.provider_conversation_id,
            "provider_thread_id": self.provider_thread_id,
            "provider_session_id": self.provider_session_id,
            "metadata": dict(self.metadata),
        }


@dataclass(slots=True, kw_only=True)
class ChatRequest:
    """一次 chat 调用的统一 envelope。"""

    stage: ProviderStage
    messages: list[Any] = field(default_factory=list)
    model: str = ""
    temperature: float = 0.2
    max_tokens: int = 1024
    response_format: dict[str, Any] | None = None
    context: ProviderRequestContext | None = None
    conversation_policy: ConversationPolicy = "stateless"
    conversation: ProviderConversationHandle | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return msgspec.to_builtins(self)


@dataclass(slots=True, kw_only=True)
class EmbeddingRequest:
    """一次 embedding 调用的统一 envelope。"""

    stage: ProviderStage = "embedding"
    texts: list[str] = field(default_factory=list)
    model: str = ""
    context: ProviderRequestContext | None = None
    conversation_policy: ConversationPolicy = "stateless"
    conversation: ProviderConversationHandle | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return msgspec.to_builtins(self)


@dataclass(slots=True, kw_only=True)
class ProviderResponseContext:
    """统一的 provider 响应上下文样例。"""

    request_id: str = ""
    session_id: str = ""
    user_id: str = ""
    stage: ProviderStage = "other"
    provider_name: str = ""
    model: str = ""
    conversation: ProviderConversationHandle | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "request_id": self.request_id,
            "session_id": self.session_id,
            "user_id": self.user_id,
            "stage": self.stage,
            "provider_name": self.provider_name,
            "model": self.model,
            "conversation": self.conversation.to_dict() if self.conversation else None,
            "metadata": dict(self.metadata),
        }
