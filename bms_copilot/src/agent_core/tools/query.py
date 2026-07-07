import re
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


# 常见的鸟种名关键词（中英文），用于启发式提取
_CHINESE_SPECIES_KEYWORDS = [
    "白颊噪鹛", "大山雀", "八哥", "麻雀", "喜鹊", "乌鸦", "燕子",
    "白头鹎", "乌鸫", "斑鸠", "啄木鸟", "翠鸟", "画眉", "黄鹂",
    "杜鹃", "猫头鹰", "鹰", "隼", "鹤", "鹭", "雁", "鸭",
]


def _heuristic_query(text: str) -> dict[str, Any]:
    """关键词启发式：从自然语言生成结构化查询（临时 fallback）。"""
    normalized = text.lower().strip()

    # 提取可能的物种名（学名或中文名）
    species_filter = _extract_species_filter(text)

    # 设备相关
    if any(kw in normalized for kw in ["设备", "站点", "device"]):
        return {
            "source": "mysql",
            "table": "device_entities",
            "filter": species_filter or {},
            "limit": 50,
        }

    # 鸟种简介
    if any(kw in normalized for kw in ["简介", "介绍", "物种", "百科", "说明"]):
        return {
            "source": "mysql",
            "table": "species_profiles",
            "filter": species_filter or {},
            "limit": 10,
        }

    # 监测记录（含按种别查询）
    has_record_kw = any(kw in normalized for kw in ["记录", "观测", "recording", "监测", "识别"])
    has_time_kw = any(
        kw in normalized for kw in ["上次", "最近", "最后", "什么时候", "时间", "何时"]
    )
    if has_record_kw or has_time_kw or species_filter:
        mongo_filter = dict(species_filter or {})
        return {
            "source": "mongo",
            "collection": "monitoring_records",
            "filter": mongo_filter,
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
        "filter": species_filter or {},
        "sort": {"captured_at_ms": -1},
        "limit": 20,
    }


def _extract_species_filter(text: str) -> dict[str, str] | None:
    """从查询文本中尝试提取物种名，返回 MongoDB 过滤条件。"""
    # 尝试匹配学名：Latin binomial (Genus species)
    scientific_match = re.search(r"[A-Z][a-z]+\s+[a-z]+", text)
    if scientific_match:
        name = scientific_match.group(0).strip()
        return {"scientific_name": name}

    # 尝试匹配中文鸟种名
    for keyword in _CHINESE_SPECIES_KEYWORDS:
        if keyword in text:
            return {"species_name": keyword}

    # 尝试匹配常见英文种名
    # 如果文本包含可能是 species 名称的单词（非通用词）
    common_words = {"上次", "最近", "最后", "什么", "时候", "时间", "识别"}
    words = set(re.findall(r"[a-zA-Z]+", text.lower()))
    meaningful = words - common_words
    for w in meaningful:
        if len(w) > 4:  # 长度大于 4 的单词可能是种名
            return {"species_name": w, "scientific_name": w}

    return None
