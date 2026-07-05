from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from src.iface.agent.audit import AgentAuditEvent, IAgentAuditSink
from src.iface.agent.tools import IToolRegistry
from src.iface.agent.runtime import AgentRuntimeContext
from src.models.agent.schemas import (
    AgentRequest,
    ToolCall,
    ToolError,
    ToolResult,
    ToolStatus,
)


@dataclass(slots=True)
class ToolExecutionHooks:
    before_call: list[Any] = field(default_factory=list)
    after_call: list[Any] = field(default_factory=list)


class ToolExecutor:
    """工具执行器样例。

    这里保留了 audit hook，但不把审计写死到执行逻辑里。
    """

    def __init__(
        self,
        tool_registry: IToolRegistry,
        *,
        audit_sink: IAgentAuditSink | None = None,
    ) -> None:
        self.tool_registry = tool_registry
        self.audit_sink = audit_sink

    async def execute(
        self,
        req: AgentRequest,
        tool_calls: list[ToolCall],
        context: AgentRuntimeContext | None = None,
    ) -> list[ToolResult]:
        results: list[ToolResult] = []
        for call in tool_calls:
            if self.audit_sink is not None:
                await self.audit_sink.record(
                    AgentAuditEvent(
                        event_name="tool_call",
                        request_id=req.request_id,
                        session_id=req.session_id,
                        stage="execution",
                        payload={
                            "tool_name": call.tool_name,
                            "arguments": call.arguments,
                        },
                    )
                )
            if not self.tool_registry.has(call.tool_name):
                result = ToolResult(
                    tool_name=call.tool_name,
                    status=ToolStatus.ERROR,
                    error=ToolError(
                        code="TOOL_NOT_FOUND",
                        message=f"tool not found: {call.tool_name}",
                    ),
                    latency_ms=0,
                )
                results.append(result)
                continue

            tool = self.tool_registry.get(call.tool_name)
            try:
                result = await tool.execute(call, req)
            except Exception as exc:  # pragma: no cover - defensive fallback
                result = ToolResult(
                    tool_name=call.tool_name,
                    status=ToolStatus.ERROR,
                    error=ToolError(code="TOOL_EXECUTION_FAILED", message=str(exc)),
                    latency_ms=0,
                )
            results.append(result)

            if self.audit_sink is not None:
                await self.audit_sink.record(
                    AgentAuditEvent(
                        event_name="tool_result",
                        request_id=req.request_id,
                        session_id=req.session_id,
                        stage="execution",
                        payload=result.model_dump(),
                    )
                )
        return results
