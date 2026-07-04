from __future__ import annotations

from typing import Any

from msgspec import Struct, field


class AttachmentMeta(Struct):
    """附件元数据，描述一次输入附件的基本信息。"""

    attachment_id: str
    session_id: str
    user_id: str
    provider: str | None = None
    model: str | None = None
    filename: str | None = None
    content_type: str | None = None
    size_bytes: int | None = None


class InferenceResultSnapshot(Struct):
    """一次图片识别推理结果的快照。"""

    request_id: str
    session_id: str
    user_id: str
    provider: str | None = None
    model: str | None = None
    intent_type: str | None = None
    confidence: float | None = None
    slots: dict[str, Any] = field(default_factory=dict)
    need_rag: bool | None = None
    tool_plan_hint: list[str] = field(default_factory=list)
    tool_name: str | None = None
    tool_arguments: dict[str, Any] = field(default_factory=dict)
    tool_timeout_ms: int | None = None


class QueryResultSnapshot(Struct):
    """一次查询结果快照，通常用于搜索或统计摘要。"""

    request_id: str
    session_id: str
    user_id: str
    provider: str | None = None
    model: str | None = None
    text: str | None = None
    structured: dict[str, Any] = field(default_factory=dict)
    cards: list[dict[str, Any]] = field(default_factory=list)
