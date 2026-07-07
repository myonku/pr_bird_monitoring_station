from src.agent_core.prompot.base import PromptTemplate

ANSWER_PROMPT = PromptTemplate(
    name="answer.synthesizer",
    kind="answer",
    version="v1",
    description="结果整合与回答生成 prompt 样例。",
    template=(
        "请基于用户问题、工具结果和引用证据生成最终回答。\n"
        "要求：\n"
        "1. 优先使用事实结果。\n"
        "2. 需要时给出简短解释。\n"
        "3. 若证据不足，明确说明不足。\n"
        "用户问题：{user_text}\n"
        "工具结果：{tool_results}\n"
        "引用证据：{citations}"
    ),
    variables=["user_text", "tool_results", "citations"],
)
