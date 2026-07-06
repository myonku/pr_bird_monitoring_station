from typing import Protocol

from src.models.agent.audit import AgentAuditEvent



class IAgentAuditSink(Protocol):
    async def record(self, event: AgentAuditEvent) -> None: ...