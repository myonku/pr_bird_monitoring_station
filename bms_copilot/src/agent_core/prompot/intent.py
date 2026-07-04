from __future__ import annotations

from src.agent_core.prompot.base import PromptTemplate


INTENT_PROMPT = PromptTemplate(
    name="intent.classifier",
    kind="intent",
    version="v1",
    description="意图识别与槽位抽取 prompt 样例。",
    template=(
        "请根据用户输入判断意图类型，并抽取必要槽位。\n"
        "可选意图：search, statistics, inference, knowledge, composite, unknown。\n"
        "输出必须是 JSON 风格结构，不要输出多余解释。\n"
        "用户输入：{user_text}"
    ),
    variables=["user_text"],
)