from msgspec import Struct


class UserInput(Struct):
    """用户输入，主体为文本"""
    ...



class IntentResult(Struct):
    """意图识别结果"""
    ...


class ToolCallPlan(Struct):
    """工具调用计划"""
    ...


class ToolResult(Struct):
    """工具调用结果"""
    ...


class AgentResponse(Struct):
    """Agent的响应"""
    ...