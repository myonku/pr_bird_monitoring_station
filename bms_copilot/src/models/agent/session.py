from __future__ import annotations

from typing import Any, Literal

from msgspec import Struct, field

SessionStatus = Literal["active", "idle", "closed", "failed"]


class AgentSession(Struct, kw_only=True):
    """会话主记录，保存当前会话的运行状态和最近上下文。"""

    session_id: str
    user_id: str
    provider: str | None = None
    model: str | None = None
    status: SessionStatus = "active"
    created_at_ms: int | None = None
    updated_at_ms: int | None = None
    last_request_id: str | None = None
    last_intent_type: str | None = None
    last_tool_name: str | None = None
    last_tool_status: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


class AgentTurn(Struct, kw_only=True):
    """一次 Agent 交互轮次的记录。"""

    request_id: str
    session_id: str
    user_id: str
    turn_index: int | None = None
    provider: str | None = None
    model: str | None = None
    intent_type: str | None = None
    status: str | None = None
    created_at_ms: int | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


class IntentRecord(Struct, kw_only=True):
    """一次意图识别结果的持久化记录。"""

    request_id: str
    session_id: str
    user_id: str
    intent_type: str
    confidence: float = 0.0
    slots: dict[str, Any] = field(default_factory=dict)
    need_rag: bool = False
    tool_plan_hint: list[str] = field(default_factory=list)
    created_at_ms: int | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


class ToolCallRecord(Struct, kw_only=True):
    """一次工具调用的持久化记录。"""

    run_id: str
    request_id: str
    session_id: str
    user_id: str
    tool_name: str
    arguments: dict[str, Any] = field(default_factory=dict)
    timeout_ms: int = 3000
    created_at_ms: int | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


class ToolResultRecord(Struct, kw_only=True):
    """一次工具执行结果的持久化记录。"""

    run_id: str
    request_id: str
    session_id: str
    user_id: str
    tool_name: str
    status: str
    payload: dict[str, Any] = field(default_factory=dict)
    error_code: str | None = None
    error_message: str | None = None
    latency_ms: int | None = None
    created_at_ms: int | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


class AgentRunRecord(Struct, kw_only=True):
    """一次完整 Agent 运行的聚合记录。"""

    run_id: str
    request_id: str
    session_id: str
    user_id: str
    provider: str | None = None
    model: str | None = None
    status: str | None = None
    intent_type: str | None = None
    tool_names: list[str] = field(default_factory=list)
    answer_text: str | None = None
    started_at_ms: int | None = None
    finished_at_ms: int | None = None
    latency_ms: int | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
