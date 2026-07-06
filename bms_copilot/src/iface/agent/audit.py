from abc import ABC, abstractmethod

from src.models.agent.audit import (
    AgentAuditEvent,
    ModelRoutingPolicy,
    ProviderUsageRecord,
)


class IAgentAuditSink(ABC):
    @abstractmethod
    async def record(self, event: AgentAuditEvent) -> None: ...


class IAgentAuditRecorder(ABC):
    @abstractmethod
    async def usage_record(self, record: ProviderUsageRecord) -> None: ...
    @abstractmethod
    async def policy_record(self, record: ModelRoutingPolicy) -> None: ...
