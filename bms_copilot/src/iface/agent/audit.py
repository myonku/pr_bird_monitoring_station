from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol


@dataclass(slots=True, kw_only=True)
class AgentAuditEvent:
    event_name: str
    request_id: str
    session_id: str
    stage: str = ""
    payload: dict[str, Any] = field(default_factory=dict)


class IAgentAuditSink(Protocol):
    async def record(self, event: AgentAuditEvent) -> None: ...