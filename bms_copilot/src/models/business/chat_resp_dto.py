from typing import Any
from msgspec import Struct, field


class ChatSessionSummary(Struct, kw_only=True):
    """会话摘要，用于列表展示。"""

    session_id: str
    title: str = ""
    status: str = "active"
    message_count: int = 0
    last_text: str = ""
    created_at_ms: int = 0
    updated_at_ms: int = 0


class ChatMessageItem(Struct, kw_only=True):
    """单条聊天消息（面向客户端展示）。"""

    turn_index: int = 0
    request_id: str = ""
    role: str = "user"  # "user" | "assistant"
    text: str = ""
    intent_type: str = ""
    tool_names: list[str] = field(default_factory=list)
    created_at_ms: int = 0


class ChatSessionDetail(Struct, kw_only=True):
    """会话完整详情。"""

    session_id: str
    user_id: str
    status: str = "active"
    provider: str = ""
    model: str = ""
    messages: list[ChatMessageItem] = field(default_factory=list)
    created_at_ms: int = 0
    updated_at_ms: int = 0


class ChatSendResponse(Struct, kw_only=True):
    """发送消息的响应。"""

    session_id: str
    request_id: str
    status: str = ""  # "ok" | "partial" | "error"
    text: str = ""
    intent_type: str = ""
    tool_names: list[str] = field(default_factory=list)
    structured: dict[str, Any] = field(default_factory=dict)
    citations: list[dict[str, str]] = field(default_factory=list)
    latency_ms: int = 0


class ChatSessionListResponse(Struct, kw_only=True):
    """会话列表响应。"""

    sessions: list[ChatSessionSummary] = field(default_factory=list)
    total: int = 0


class ChatSessionDeleteResponse(Struct, kw_only=True):
    """删除会话响应。"""

    session_id: str
    deleted: bool = False


class ChatSessionCreateResponse(Struct, kw_only=True):
    """创建会话响应。"""

    session_id: str
    created_at_ms: int = 0
