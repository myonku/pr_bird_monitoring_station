from typing import Literal
from uuid import UUID

from msgspec import Struct, field


EventPayloadType = Literal["image", "video", "audio", "metadata", "mixed"]
ProcessingStatus = Literal["pending", "running", "succeeded", "retrying", "failed"]
RecordStatus = Literal["received", "normalized", "stored", "published", "failed"]
ProcessingSource = Literal["edge", "data_worker"]


class UserProfile(Struct, frozen=True):
    """安全性较低的用户信息，用于业务相关的展示和处理，避免直接使用认证模块中的用户信息结构。"""

    user_entity_id: UUID
    username: str
    display_name: str = ""
    email: str = ""
    phone: str = ""
    role: str = ""
    avatar_binary: bytes = b""
    avatar_content_type: str = ""
    metadata: dict[str, str] = field(default_factory=dict)


class EventBinaryPart(Struct, frozen=True):
    """边缘事件中的二进制片段引用。"""

    part_id: UUID
    name: str
    content_type: str
    size_bytes: int
    sha256: str = ""
    mongo_document_id: str = ""
    storage_key: str = ""
    metadata: dict[str, str] = field(default_factory=dict)


class EdgeEventEnvelope(Struct, kw_only=True):
    """边缘端上传事件的接入模型。"""

    event_id: UUID
    station_entity_id: UUID
    occurred_at_ms: int
    received_at_ms: int
    payload_version: str
    payload_type: EventPayloadType
    payload_body: dict[str, object] = field(default_factory=dict)
    payload_mongo_ref: str = ""
    binary_parts: list[EventBinaryPart] = field(default_factory=list)
    transport_meta: dict[str, str] = field(default_factory=dict)
    metadata: dict[str, str] = field(default_factory=dict)


class ProcessingJob(Struct, kw_only=True):
    """一次事件处理任务。"""

    job_id: UUID
    source_event_id: UUID
    station_entity_id: UUID
    status: ProcessingStatus
    processor: str = ""
    retry_count: int = 0
    started_at_ms: int = 0
    finished_at_ms: int = 0
    error_message: str = ""
    metadata: dict[str, str] = field(default_factory=dict)


class RecognitionResult(Struct, kw_only=True):
    """模型识别或补充识别结果。"""

    result_id: UUID
    source_event_id: UUID
    species_entity_id: UUID | None = None
    species_name: str
    scientific_name: str = ""
    confidence: float = 0.0
    model_name: str = ""
    model_version: str = ""
    produced_by: ProcessingSource
    metadata: dict[str, str] = field(default_factory=dict)


class MonitoringRecord(Struct, kw_only=True):
    """标准业务记录。"""

    record_id: UUID
    station_entity_id: UUID
    source_event_id: UUID
    species_entity_id: UUID | None = None
    captured_at_ms: int
    species_name: str
    scientific_name: str = ""
    confidence: float = 0.0
    temperature_c: float | None = None
    humidity_pct: int | None = None
    media_refs: list[str] = field(default_factory=list)
    processing_source: ProcessingSource
    model_version: str = ""
    summary_text: str = ""
    species_intro: str = ""
    record_status: RecordStatus = "received"
    metadata: dict[str, str] = field(default_factory=dict)
