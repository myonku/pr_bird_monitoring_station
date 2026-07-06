from src.iface.agent.audit import IAgentAuditRecorder, IAgentAuditSink
from src.models.agent.audit import (
    AgentAuditEvent,
    ModelRoutingPolicy,
    ProviderUsageRecord,
)


class AuditSink(IAgentAuditSink):
    """基于 Beanie ODM 的审计日志 Sink。"""

    def __init__(self, document_model: type[AgentAuditEvent] = AgentAuditEvent) -> None:
        self._document_model = document_model

    async def record(self, event: AgentAuditEvent) -> None:
        await event.insert()


class AuditRecorder(IAgentAuditRecorder):
    """审计日志记录器，支持多种审计事件的记录。"""

    def __init__(
        self,
        usage_model: type[AgentAuditEvent] = AgentAuditEvent,
        policy_model: type[AgentAuditEvent] = AgentAuditEvent,
    ) -> None:
        self._usage_model = usage_model
        self._policy_model = policy_model

    async def usage_record(self, record: ProviderUsageRecord) -> None:
        await record.insert()

    async def policy_record(self, record: ModelRoutingPolicy) -> None:
        await record.insert()
