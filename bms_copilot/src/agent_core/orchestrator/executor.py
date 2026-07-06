from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import time

from src.iface.agent.audit import AgentAuditEvent, IAgentAuditSink
from src.iface.agent.tools import IToolRegistry
from src.iface.agent_resource.tool_trace_store import IToolTraceStore
from src.iface.agent.runtime import AgentRuntimeContext
from src.models.agent.schemas import (
    AgentRequest,
    ToolCall,
    ToolError,
    ToolResult,
    ToolStatus,
)
from src.models.agent.tool_record import ToolCallRecord, ToolResultRecord


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
        trace_store: IToolTraceStore | None = None,
    ) -> None:
        self.tool_registry = tool_registry
        self.audit_sink = audit_sink
        self._trace_store = trace_store

    async def execute(
        self,
        req: AgentRequest,
        tool_calls: list[ToolCall],
        context: AgentRuntimeContext | None = None,
    ) -> list[ToolResult]:
        results: list[ToolResult] = []
        run_id = _resolve_run_id(context)

        for call in tool_calls:
            await self._trace_tool_call(run_id, req, call)

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

            await self._trace_tool_result(run_id, req, call, result)

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

    async def _trace_tool_call(
        self,
        run_id: str,
        req: AgentRequest,
        call: ToolCall,
    ) -> None:
        store = self._trace_store
        if store is None:
            return
        now = int(time.time() * 1000)
        await store.save_tool_call(
            ToolCallRecord(
                run_id=run_id,
                request_id=req.request_id,
                session_id=req.session_id,
                user_id=req.user_id,
                tool_name=call.tool_name,
                arguments=dict(call.arguments),
                timeout_ms=call.timeout_ms,
                created_at_ms=now,
            )
        )

    async def _trace_tool_result(
        self,
        run_id: str,
        req: AgentRequest,
        call: ToolCall,
        result: ToolResult,
    ) -> None:
        store = self._trace_store
        if store is None:
            return
        now = int(time.time() * 1000)
        await store.save_tool_result(
            ToolResultRecord(
                run_id=run_id,
                request_id=req.request_id,
                session_id=req.session_id,
                user_id=req.user_id,
                tool_name=call.tool_name,
                status=result.status.value if hasattr(result.status, "value") else str(result.status),
                payload=dict(result.payload),
                error_code=result.error.code if result.error else None,
                error_message=result.error.message if result.error else None,
                latency_ms=result.latency_ms,
                created_at_ms=now,
            )
        )


def _resolve_run_id(context: AgentRuntimeContext | None) -> str:
    if context is not None:
        rid = context.metadata.get("run_id")
        if rid:
            return str(rid)
    return ""
