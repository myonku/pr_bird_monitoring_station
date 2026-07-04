from __future__ import annotations

from enum import Enum
from typing import Any
from pydantic import BaseModel, Field


class IntentType(str, Enum):
    """Agent 支持的意图类型枚举。"""

    SEARCH = "search"
    STATISTICS = "statistics"
    INFERENCE = "inference"
    KNOWLEDGE = "knowledge"
    COMPOSITE = "composite"
    UNKNOWN = "unknown"


class RunStatus(str, Enum):
    """一次 Agent 运行的整体状态。"""

    OK = "ok"
    PARTIAL = "partial"
    ERROR = "error"


class ToolStatus(str, Enum):
    """单个工具调用的执行状态。"""

    OK = "ok"
    ERROR = "error"
    TIMEOUT = "timeout"


class ImageRef(BaseModel):
    """输入请求中的图片数据。"""

    image_id: str | None = None
    data: bytes
    mime_type: str = "image/jpeg"
    filename: str | None = None
    size_bytes: int | None = None


class RequestContext(BaseModel):
    """请求的运行环境与客户端上下文。"""

    locale: str = "zh-CN"
    timezone: str = "Asia/Shanghai"
    client_type: str = "app"


class RequestMeta(BaseModel):
    """请求追踪元数据。"""

    trace_id: str | None = None
    timestamp_ms: int | None = None


class AgentRequest(BaseModel):
    """Agent 对外接收的标准输入结构。"""

    request_id: str
    session_id: str
    user_id: str
    text: str
    images: list[ImageRef] = Field(default_factory=list)
    context: RequestContext = Field(default_factory=RequestContext)
    metadata: RequestMeta = Field(default_factory=RequestMeta)


class IntentResult(BaseModel):
    """意图识别后的标准输出。"""

    intent_type: IntentType
    confidence: float = 0.0
    slots: dict[str, Any] = Field(default_factory=dict)
    need_rag: bool = False
    tool_plan_hint: list[str] = Field(default_factory=list)


class ToolCall(BaseModel):
    """计划阶段生成的工具调用描述。"""

    tool_name: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    timeout_ms: int = 3000


class ToolError(BaseModel):
    """工具执行失败时返回的错误信息。"""

    code: str
    message: str


class ToolResult(BaseModel):
    """工具执行完成后的统一结果。"""

    tool_name: str
    status: ToolStatus
    payload: dict[str, Any] = Field(default_factory=dict)
    error: ToolError | None = None
    latency_ms: int = 0


class Citation(BaseModel):
    """回答中引用的证据片段。"""

    source_id: str
    title: str
    snippet: str


class AnswerPayload(BaseModel):
    """最终答案的文本与结构化承载。"""

    text: str
    structured: dict[str, Any] = Field(default_factory=dict)
    cards: list[dict[str, Any]] = Field(default_factory=list)


class DebugTrace(BaseModel):
    """用于调试和回放的轻量轨迹信息。"""

    intent: str = "unknown"
    tools: list[str] = Field(default_factory=list)
    provider: str | None = None
    model: str | None = None


class AgentResponse(BaseModel):
    """Agent 对外返回的标准响应。"""

    request_id: str
    session_id: str
    status: RunStatus
    answer: AnswerPayload
    citations: list[Citation] = Field(default_factory=list)
    debug: DebugTrace = Field(default_factory=DebugTrace)
