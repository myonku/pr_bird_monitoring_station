from __future__ import annotations

from src.agent_core.prompot.base import PromptTemplate


TOOL_ROUTER_PROMPT = PromptTemplate(
    name="tool.router",
    kind="tool_router",
    version="v1",
    description="工具选择与执行计划 prompt 样例。",
    template=(
        "根据意图和上下文生成工具调用计划。\n"
        "要求输出 tool_name、arguments、timeout_ms。\n"
        "如果不需要工具，返回空数组。\n"
        "意图：{intent}\n"
        "上下文：{context}\n"
        "可用工具：{available_tools}"
    ),
    variables=["intent", "context", "available_tools"],
)