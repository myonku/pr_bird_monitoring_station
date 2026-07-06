from typing import Any
from msgspec import Struct, field
from src.models.common.types import UUIDDocument



class AgentAuditEvent(UUIDDocument):
    """Agent审计事件"""

    event_name: str
    request_id: str
    session_id: str
    stage: str = ""
    payload: dict[str, Any] = field(default_factory=dict)


class ProviderUsageRecord(Struct):
    """一次Provider使用记录"""

    request_id: str
    session_id: str
    user_id: str
    provider: str
    model: str
    prompt_tokens: int | None = None
    completion_tokens: int | None = None
    total_tokens: int | None = None


class ModelRoutingPolicy(Struct):
    """模型路由策略记录"""

    session_id: str
    user_id: str
    provider: str
    model: str
    policy_name: str
    policy_params: dict[str, Any] = field(default_factory=dict)


class PromptTemplateVersion(Struct):
    """Prompt模板版本记录"""

    template_id: str
    version_id: str
    session_id: str
    user_id: str
    provider: str | None = None
    model: str | None = None
    version_number: int | None = None
