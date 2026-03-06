from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any, Literal
import time
import uuid


def _now_ms() -> int:
    return int(time.time() * 1000)

@dataclass
class DeviceInfo:
    """设备基本信息，用于会话验证"""
    device_id: str
    model: str
    firmware_version: str
    location: str | None = None
    dev_secret: str | None = None

@dataclass
class CaptureContext:
    """捕拍上下文信息"""
    device_id: str
    trigger_type: Literal["motion", "scheduled", "manual"] = "motion"
    sensor_snapshot: dict[str, Any] = field(default_factory=dict)
    captured_at_ms: int = field(default_factory=_now_ms)


@dataclass
class ImagePayload:
    """图像数据及相关信息"""
    image_id: str
    bytes_data: bytes
    format: str = "jpg"
    width: int | None = None
    height: int | None = None
    checksum: str | None = None


@dataclass
class InferenceResult:
    """本地推理结果"""
    model_version: str
    top1_label: str | None = None
    top1_confidence: float | None = None
    topk: list[dict[str, Any]] = field(default_factory=list)
    latency_ms: int | None = None
    success: bool = True
    reason: str | None = None


@dataclass
class EdgeEvent:
    """边缘事件数据结构，包含捕拍上下文、图像数据和本地推理结果等信息"""
    event_id: str
    trace_id: str
    context: CaptureContext
    image: ImagePayload
    local_inference: InferenceResult | None = None
    requires_server_assist: bool = False # 是否需要云端辅助识别（如本地推理结果不确定或失败）
    metadata: dict[str, Any] = field(default_factory=dict)

    @staticmethod
    def new(context: CaptureContext, image: ImagePayload) -> "EdgeEvent":
        return EdgeEvent(
            event_id=str(uuid.uuid4()),
            trace_id=str(uuid.uuid4()),
            context=context,
            image=image,
        )
