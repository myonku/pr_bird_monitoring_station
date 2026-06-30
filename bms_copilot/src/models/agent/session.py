from msgspec import Struct, field


class AgentSession(Struct):
    """会话模型，作为会话凭据"""
    session_id: str
    user_id: str
    provider: str | None = None
    model: str | None = None


class AgentTurn(Struct):
    """一次Agent交互轮次的记录"""
    request_id: str
    session_id: str
    user_id: str
    provider: str | None = None
    model: str | None = None


class IntentRecord(Struct):
    """一次意图识别记录"""

    request_id: str
    session_id: str
    user_id: str
    intent_type: str
    confidence: float = 0.0
    slots: dict[str, str] = field(default_factory=dict)
    need_rag: bool = False
    tool_plan_hint: list[str] = field(default_factory=list)


class ToolCallRecord(Struct):
    """一次工具调用记录"""

    request_id: str
    session_id: str
    user_id: str
    tool_name: str
    arguments: dict[str, str] = field(default_factory=dict)
    timeout_ms: int = 3000


class AgentRunRecord(Struct):
    """一次完整的Agent运行记录，包括请求、意图识别、工具调用和响应"""

    ...
