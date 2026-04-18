from __future__ import annotations

from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from src.models.business.data import EdgeEventEnvelope
from src.models.inference.workflow import (
    TwoStageInferenceResult,
)


EdgeTriggerType = Literal["motion", "scheduled", "manual"]


class TemperatureHumiditySnapshotRequest(BaseModel):
    """边缘端环境传感器快照。"""

    temperature_c: float | None = None
    humidity_pct: int | None = None
    source: str = "pseudo_mock"
    sensor_snapshot: dict[str, Any] = Field(default_factory=dict)
    captured_at_ms: int = 0

    model_config = ConfigDict(populate_by_name=True, extra="allow")


class CaptureContextRequest(BaseModel):
    """边缘端采集上下文。"""

    device_id: str
    device_name: str = "unknown"
    location_name: str = "unknown"
    trigger_type: EdgeTriggerType = "motion"
    sensor_snapshot: dict[str, Any] = Field(default_factory=dict)
    environment_snapshot: TemperatureHumiditySnapshotRequest | None = None
    captured_at_ms: int = 0

    model_config = ConfigDict(populate_by_name=True, extra="allow")


class ImagePayloadRequest(BaseModel):
    """边缘端上传的图像元信息。"""

    image_id: str
    format: str = "jpg"
    width: int | None = None
    height: int | None = None
    checksum_sha256: str | None = None

    model_config = ConfigDict(populate_by_name=True, extra="allow")


class EdgeEventUploadRequest(BaseModel):
    """边缘端上传到 data_worker 的真实请求模型。"""

    event_id: UUID
    trace_id: UUID
    context: CaptureContextRequest
    image: ImagePayloadRequest
    local_inference: TwoStageInferenceResult | None = None
    requires_server_assist: bool = False
    metadata: dict[str, Any] = Field(default_factory=dict)
    image_b64: str = ""

    model_config = ConfigDict(populate_by_name=True, extra="allow")

    def to_document(self, payload_version: str = "edge_event_http_v1") -> EdgeEventEnvelope:
        """把请求快照转成可持久化的事件信封。

        这个转换只用于 data_worker 内部沉淀，不改变对外请求模型本身。
        """
        device_entity_id = self._parse_uuid(self.context.device_id, field_name="context.device_id")
        payload_body = self.model_dump(mode="python")
        return EdgeEventEnvelope(
            _id=self.event_id,
            device_entity_id=device_entity_id,
            device_name=self.context.device_name,
            occurred_at_ms=self.context.captured_at_ms,
            received_at_ms=self.context.captured_at_ms,
            payload_version=payload_version,
            payload_type="mixed",
            payload_body=payload_body,
            payload_mongo_document_id="",
            binary_parts=[],
            transport_meta={"source": "edge_server", "content_type": "application/json"},
            metadata=dict(self.metadata or {}),
        )

    @staticmethod
    def _parse_uuid(raw: str, *, field_name: str) -> UUID:
        candidate = (raw or "").strip()
        if not candidate:
            raise ValueError(f"{field_name} is required")
        try:
            return UUID(candidate)
        except ValueError as exc:
            raise ValueError(f"{field_name} must be a valid UUID") from exc