from __future__ import annotations

from typing import Any

from msgspec import Struct, field


class SessionWorkingState(Struct):
    """会话工作状态模型，缓存记录会话的当前状态"""

    session_id: str
    user_id: str
    provider: str | None = None
    model: str | None = None
    last_request_id: str | None = None
    last_intent_type: str | None = None
    last_tool_name: str | None = None
    last_tool_status: str | None = None
    last_tool_result: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)


class InFlightRunLock(Struct):
    """会话运行锁模型，确保同一会话的并发请求不会互相干扰"""

    session_id: str
    user_id: str
    request_id: str
    acquired_at_ms: int | None = None


class IdempotencyKey(Struct):
    """幂等性Key模型，确保同一请求不会被重复处理"""

    request_id: str
    session_id: str
    user_id: str
    created_at_ms: int | None = None