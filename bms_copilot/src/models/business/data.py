from typing import Literal
from uuid import UUID, uuid4

from beanie import Document
from pydantic import BaseModel, ConfigDict, Field


EventPayloadType = Literal["image", "video", "audio", "metadata", "mixed"]
RecordStatus = Literal["received", "normalized", "stored", "published", "failed"]
ProcessingSource = Literal["edge", "data_worker"]
MONITORING_CONFIDENCE_MIN = 0.8


class UUIDDocument(Document):
    id: UUID = Field(default_factory=uuid4, alias="_id") # type: ignore

    model_config = ConfigDict(populate_by_name=True)

    @property
    def document_id(self) -> UUID:
        return self.id


class UserProfile(UUIDDocument):
    """安全性较低的用户信息，仅用于业务侧展示和处理，不包含敏感信息。"""

    username: str
    display_name: str = ""
    email: str = ""
    phone: str = ""
    role: str = "user"
    avatar_b64: str = ""
    metadata: dict[str, str] = Field(default_factory=dict)

    class Settings:
        name = "user_profiles"

    @property
    def user_entity_id(self) -> UUID:
        return self.id


class EventBinaryPart(BaseModel):
    """边缘事件携带的二进制数据片段，作为嵌入式结构存储。"""

    part_id: UUID = Field(default_factory=uuid4)
    name: str
    content_type: str
    size_bytes: int
    sha256: str = ""
    mongo_document_id: str = ""
    metadata: dict[str, str] = Field(default_factory=dict)

    model_config = ConfigDict(populate_by_name=True)


class EdgeEventEnvelope(UUIDDocument):
    """边缘事件的入站封装对象，包含事件主体和相关的二进制数据片段。"""

    device_entity_id: UUID
    device_name: str = "unknown"
    occurred_at_ms: int
    received_at_ms: int
    payload_version: str
    payload_type: EventPayloadType
    payload_body: dict[str, object] = Field(default_factory=dict)
    payload_mongo_document_id: str = ""
    binary_parts: list[EventBinaryPart] = Field(default_factory=list)
    transport_meta: dict[str, str] = Field(default_factory=dict)
    metadata: dict[str, str] = Field(default_factory=dict)

    class Settings:
        name = "edge_event_envelopes"

    @property
    def event_id(self) -> UUID:
        return self.id


class MonitoringRecord(UUIDDocument):
    """一次监测记录的业务模型，包含监测到的物种信息、环境信息、原图、媒体信息、处理来源等。"""

    device_entity_id: UUID
    device_name: str = "unknown"
    source_event_id: UUID
    species_entity_id: UUID | None = None
    captured_at_ms: int
    species_name: str
    scientific_name: str = ""
    confidence: float = 0.0
    temperature_c: float | None = None
    humidity_pct: int | None = None
    image_b64: str = ""
    media_refs: list[str] = Field(default_factory=list)
    processing_source: ProcessingSource
    model_version: str = ""
    summary_text: str = ""
    species_intro: str = ""
    record_status: RecordStatus = "received"
    metadata: dict[str, str] = Field(default_factory=dict)

    class Settings:
        name = "monitoring_records"

    @property
    def record_id(self) -> UUID:
        return self.id


BUSINESS_DOCUMENT_MODELS = [UserProfile, EdgeEventEnvelope, MonitoringRecord]
