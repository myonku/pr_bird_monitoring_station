from abc import abstractmethod
from typing import Protocol

from src.models.agent.audit import (
    AgentAuditEvent,
    ModelRoutingPolicy,
    ProviderUsageRecord,
)


class IAgentAuditSink(Protocol):
    @abstractmethod
    async def record(self, event: AgentAuditEvent) -> None: ...


class IAgentAuditRecorder(Protocol):
    @abstractmethod
    async def usage_record(self, record: ProviderUsageRecord) -> None: ...
    @abstractmethod
    async def policy_record(self, record: ModelRoutingPolicy) -> None: ...
