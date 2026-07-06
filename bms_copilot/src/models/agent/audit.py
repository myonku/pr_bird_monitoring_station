from typing import Any
from uuid import UUID

from pydantic import Field

from src.models.common.types import UUIDDocument


class AgentAuditEvent(UUIDDocument):
    """Agent审计事件"""

    event_name: str
    request_id: str
    session_id: str
    stage: str = ""
    payload: dict[str, Any] = Field(default_factory=dict)

    class Settings:
        name = "agent_audit_events"

    @property
    def event_id(self) -> UUID:
        return self.id


class ProviderUsageRecord(UUIDDocument):
    """一次Provider使用记录"""

    request_id: str
    session_id: str
    user_id: str
    provider: str
    model: str
    prompt_tokens: int | None = None
    completion_tokens: int | None = None
    total_tokens: int | None = None

    class Settings:
        name = "provider_usage_records"

    @property
    def record_id(self) -> UUID:
        return self.id


class ModelRoutingPolicy(UUIDDocument):
    """模型路由策略记录"""

    session_id: str
    user_id: str
    provider: str
    model: str
    policy_name: str
    policy_params: dict[str, Any] = Field(default_factory=dict)

    class Settings:
        name = "model_routing_policies"

    @property
    def policy_id(self) -> UUID:
        return self.id


class PromptTemplateVersion(UUIDDocument):
    """Prompt模板版本记录"""

    template_id: str
    version_id: str
    session_id: str
    user_id: str
    provider: str | None = None
    model: str | None = None
    version_number: int | None = None

    class Settings:
        name = "prompt_template_versions"
    
    @property
    def version_record_id(self) -> UUID:
        return self.id
