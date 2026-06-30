from __future__ import annotations

from enum import Enum
from typing import Any
from pydantic import BaseModel, Field


class IntentType(str, Enum):
    SEARCH = "search"
    STATISTICS = "statistics"
    INFERENCE = "inference"
    KNOWLEDGE = "knowledge"
    COMPOSITE = "composite"
    UNKNOWN = "unknown"


class RunStatus(str, Enum):
    OK = "ok"
    PARTIAL = "partial"
    ERROR = "error"


class ToolStatus(str, Enum):
    OK = "ok"
    ERROR = "error"
    TIMEOUT = "timeout"


class ImageRef(BaseModel):
    image_id: str
    uri: str
    mime_type: str = "image/jpeg"


class RequestContext(BaseModel):
    locale: str = "zh-CN"
    timezone: str = "Asia/Shanghai"
    client_type: str = "app"


class RequestMeta(BaseModel):
    trace_id: str | None = None
    timestamp_ms: int | None = None


class AgentRequest(BaseModel):
    request_id: str
    session_id: str
    user_id: str
    text: str
    images: list[ImageRef] = Field(default_factory=list)
    context: RequestContext = Field(default_factory=RequestContext)
    metadata: RequestMeta = Field(default_factory=RequestMeta)


class IntentResult(BaseModel):
    intent_type: IntentType
    confidence: float = 0.0
    slots: dict[str, Any] = Field(default_factory=dict)
    need_rag: bool = False
    tool_plan_hint: list[str] = Field(default_factory=list)


class ToolCall(BaseModel):
    tool_name: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    timeout_ms: int = 3000


class ToolError(BaseModel):
    code: str
    message: str


class ToolResult(BaseModel):
    tool_name: str
    status: ToolStatus
    payload: dict[str, Any] = Field(default_factory=dict)
    error: ToolError | None = None
    latency_ms: int = 0


class Citation(BaseModel):
    source_id: str
    title: str
    snippet: str


class AnswerPayload(BaseModel):
    text: str
    structured: dict[str, Any] = Field(default_factory=dict)
    cards: list[dict[str, Any]] = Field(default_factory=list)


class DebugTrace(BaseModel):
    intent: str = "unknown"
    tools: list[str] = Field(default_factory=list)
    provider: str | None = None
    model: str | None = None


class AgentResponse(BaseModel):
    request_id: str
    session_id: str
    status: RunStatus
    answer: AnswerPayload
    citations: list[Citation] = Field(default_factory=list)
    debug: DebugTrace = Field(default_factory=DebugTrace)
