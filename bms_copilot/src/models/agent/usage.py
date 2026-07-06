import time
from uuid import UUID
from pydantic import Field
from msgspec import Struct

from src.models.common.types import UUIDDocument


def _now_ms() -> int:
    return int(time.time() * 1000)


class UsageRecord(UUIDDocument):
    """单次 LLM 调用的用量记录（MongoDB/Beanie 持久化）。"""

    run_id: str
    request_id: str
    session_id: str
    user_id: str
    stage: str = ""
    provider: str = ""
    model: str = ""
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    latency_ms: int | None = None
    created_at_ms: int = Field(default_factory=_now_ms)

    class Settings:
        name = "agent_usage_records"

    @property
    def record_id(self) -> UUID:
        return self.id


class SessionUsageSummary(Struct, kw_only=True):
    """一次会话的用量聚合摘要（纯数据结构）。"""

    session_id: str
    total_calls: int = 0
    total_prompt_tokens: int = 0
    total_completion_tokens: int = 0
    total_tokens: int = 0
    by_stage: dict[str, int] = Field(default_factory=dict)
    by_model: dict[str, int] = Field(default_factory=dict)
