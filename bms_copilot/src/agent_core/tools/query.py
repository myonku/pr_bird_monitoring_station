import time
from typing import Any

from src.iface.agent.tools import ITool
from src.models.agent.schemas import (
    AgentRequest,
    ToolCall,
    ToolResult,
    ToolStatus,
)
from src.modules.query.engine import QueryEngine


class QueryRecordsTool(ITool):
    """数据查询工具：LLM 生成结构化查询 → 应用侧执行。

    覆盖监测记录查询、设备信息查询、鸟种简介查询、统计聚合等。
    """

    name = "query_records_tool"
    description = "查询监测记录、设备信息、鸟种简介、统计数据"

    def __init__(
        self,
        engine: QueryEngine,
    ) -> None:
        if engine is None:
            raise ValueError("engine is required")
        self._engine = engine

    async def execute(self, call: ToolCall, req: AgentRequest) -> ToolResult:
        start = time.time()

        # 优先使用 planner 传入的 query_spec，没有时走启发式 fallback
        query_spec = (call.arguments or {}).get("query_spec")
        if not query_spec or not isinstance(query_spec, dict):
            query_text = (call.arguments or {}).get("query") or req.text
            query_spec = _heuristic_query(query_text)

        result = await self._engine.execute(query_spec)

        return ToolResult(
            tool_name=self.name,
            status=ToolStatus.OK,
            payload=result,
            latency_ms=int((time.time() - start) * 1000),
        )


def _heuristic_query(text: str) -> dict[str, Any]:
    """关键词启发式：从自然语言生成结构化查询（临时 fallback）。"""
    normalized = text.lower().strip()

    # 设备相关
    if any(kw in normalized for kw in ["设备", "站点", "device"]):
        return {
            "source": "mysql",
            "table": "device_entities",
            "filter": {},
            "limit": 50,
        }

    # 鸟种简介
    if any(kw in normalized for kw in ["简介", "介绍", "物种", "species"]):
        return {
            "source": "mysql",
            "table": "species_profiles",
            "filter": {},
            "limit": 20,
        }

    # 监测记录
    if any(kw in normalized for kw in ["记录", "观测", "recording", "监测"]):
        return {
            "source": "mongo",
            "collection": "monitoring_records",
            "filter": {},
            "sort": {"captured_at_ms": -1},
            "limit": 20,
        }

    # 上传事件
    if any(kw in normalized for kw in ["上传", "事件", "上报", "event"]):
        return {
            "source": "mongo",
            "collection": "edge_event_envelopes",
            "filter": {},
            "sort": {"occurred_at_ms": -1},
            "limit": 20,
        }

    # 默认：监测记录
    return {
        "source": "mongo",
        "collection": "monitoring_records",
        "filter": {},
        "sort": {"captured_at_ms": -1},
        "limit": 20,
    }
