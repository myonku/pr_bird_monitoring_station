from msgspec import Struct, field


class AttachmentMeta(Struct):
    """附件元数据模型，记录附件的基本信息"""

    attachment_id: str
    session_id: str
    user_id: str
    provider: str | None = None
    model: str | None = None
    filename: str | None = None
    content_type: str | None = None
    size_bytes: int | None = None


class InferenceResultSnapshot(Struct):
    """一次图片识别推理结果的快照"""

    request_id: str
    session_id: str
    user_id: str
    provider: str | None = None
    model: str | None = None
    intent_type: str | None = None
    confidence: float | None = None
    slots: dict[str, str] = field(default_factory=dict)
    need_rag: bool | None = None
    tool_plan_hint: list[str] = field(default_factory=list)
    tool_name: str | None = None
    tool_arguments: dict[str, str] = field(default_factory=dict)
    tool_timeout_ms: int | None = None


class QueryResultSnapshot(Struct):
    """一次查询结果(搜索/统计结果摘要)的快照"""

    request_id: str
    session_id: str
    user_id: str
    provider: str | None = None
    model: str | None = None
    text: str | None = None
    structured: dict[str, str] = field(default_factory=dict)
    cards: list[dict[str, str]] = field(default_factory=list)
