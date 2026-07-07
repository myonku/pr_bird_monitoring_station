from src.agent_core.prompot.base import PromptTemplate

TOOL_ROUTER_PROMPT = PromptTemplate(
    name="tool.router",
    kind="tool_router",
    version="v2",
    description="工具选择与执行计划 prompt。支持 query_records_tool 的数据源描述。",
    template=(
        "根据意图和上下文生成工具调用计划。\n"
        "要求输出 tool_name、arguments、timeout_ms。\n"
        "如果不需要工具，返回空数组。\n"
        "意图：{intent}\n"
        "上下文：{context}\n"
        "可用工具：{available_tools}\n"
        "如果选用 query_records_tool，arguments 中必须包含 query_spec 字段，"
        '格式为 {{"source": "mongo|mysql", "collection|table": "...", '
        '"filter": {{...}}, "sort": {{...}}, "limit": N}}。\n'
        "可查询的数据源定义：\n{schema}"
    ),
    variables=["intent", "context", "available_tools", "schema"],
)
