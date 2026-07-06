from typing import Any
from uuid import UUID

from pydantic import Field

from src.models.common.types import UUIDDocument


class ToolCallRecord(UUIDDocument):
    """一次工具调用的持久化记录。"""

    run_id: str
    request_id: str
    session_id: str
    user_id: str
    tool_name: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    timeout_ms: int = 3000
    created_at_ms: int | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    class Settings:
        name = "tool_call_records"

    @property
    def call_record_id(self) -> UUID:
        return self.id


class ToolResultRecord(UUIDDocument):
    """一次工具执行结果的持久化记录。"""

    run_id: str
    request_id: str
    session_id: str
    user_id: str
    tool_name: str
    status: str
    payload: dict[str, Any] = Field(default_factory=dict)
    error_code: str | None = None
    error_message: str | None = None
    latency_ms: int | None = None
    created_at_ms: int | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    class Settings:
        name = "tool_result_records"

    @property
    def tool_result_id(self) -> UUID:
        return self.id
