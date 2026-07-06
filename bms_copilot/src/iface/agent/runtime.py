from dataclasses import dataclass, field
from typing import Any

from src.models.agent.api import ChatMessage
from src.iface.agent.knowledge import RetrievedChunk


@dataclass(slots=True, kw_only=True)
class AgentRuntimeContext:
    """可扩展的 Agent 运行时上下文。

    预留 memory、RAG、audit 等未来组件的挂载位，但默认不强制使用。
    """

    recent_messages: list[ChatMessage] = field(default_factory=list)
    retrieved_chunks: list[RetrievedChunk] = field(default_factory=list)
    provider_state: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)
    session_state: dict[str, Any] = field(default_factory=dict)
    audit_metadata: dict[str, Any] = field(default_factory=dict)
