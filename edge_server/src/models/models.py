from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Literal


def now_ms() -> int:
    return int(time.time() * 1000)


@dataclass(slots=True)
class DeviceInfo:
    device_id: str
    model: str
    firmware_version: str
    location: str | None = None


@dataclass(slots=True)
class CaptureContext:
    device_id: str
    trigger_type: Literal["motion", "scheduled", "manual"] = "motion"
    sensor_snapshot: dict[str, Any] = field(default_factory=dict)
    captured_at_ms: int = field(default_factory=now_ms)


@dataclass(slots=True)
class ImagePayload:
    image_id: str
    bytes_data: bytes
    format: str = "jpg"
    width: int | None = None
    height: int | None = None
    checksum_sha256: str | None = None


@dataclass(slots=True)
class ModelArtifactContract:
    """训练侧与边缘侧共享的单模型协定。"""

    artifact_id: str
    task: Literal["detection", "classification"]
    tier: Literal["lightweight", "standard"]
    framework: str
    model_name: str
    format: Literal["onnx", "tflite", "torchscript", "openvino", "custom"]
    model_version: str
    artifact_path: str
    labels: list[str] = field(default_factory=list)
    input_size: tuple[int, int] = (640, 640)
    score_threshold: float = 0.25
    nms_iou_threshold: float = 0.45
    topk: int = 5
    checksum_sha256: str | None = None


@dataclass(slots=True)
class EdgeModelContract:
    """边缘端推理需要同时提供检测和分类两个模型。"""

    contract_version: str
    package_version: str
    exported_at_ms: int
    exported_by: str
    detection: ModelArtifactContract
    classification: ModelArtifactContract
    notes: str = ""


@dataclass(slots=True)
class LoadedModelBundle:
    """模型加载模块暴露给推理模块的统一模型句柄。"""

    contract: EdgeModelContract
    detection_handle: Any
    classification_handle: Any
    loaded_at_ms: int = field(default_factory=now_ms)


@dataclass(slots=True)
class DetectionBox:
    label: str
    confidence: float
    x1: float
    y1: float
    x2: float
    y2: float


@dataclass(slots=True)
class DetectionResult:
    success: bool
    boxes: list[DetectionBox] = field(default_factory=list)
    latency_ms: int | None = None
    reason: str | None = None


@dataclass(slots=True)
class ClassificationHit:
    label: str
    confidence: float


@dataclass(slots=True)
class ClassificationResult:
    success: bool
    top1_label: str | None = None
    top1_confidence: float | None = None
    topk: list[ClassificationHit] = field(default_factory=list)
    latency_ms: int | None = None
    reason: str | None = None


@dataclass(slots=True)
class TwoStageInferenceResult:
    """两阶段推理结果：先检测后分类，检测失败时提前返回。"""

    success: bool
    stage: Literal[
        "skipped",
        "detected_only",
        "classified",
        "detector_failed",
        "classifier_failed",
    ]
    detection: DetectionResult
    classification: ClassificationResult | None = None
    detector_model_version: str | None = None
    classifier_model_version: str | None = None
    reason: str | None = None


@dataclass(slots=True)
class EdgeEvent:
    event_id: str
    trace_id: str
    context: CaptureContext
    image: ImagePayload
    local_inference: TwoStageInferenceResult | None = None
    requires_server_assist: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)

    @staticmethod
    def new(context: CaptureContext, image: ImagePayload) -> "EdgeEvent":
        return EdgeEvent(
            event_id=str(uuid.uuid4()),
            trace_id=str(uuid.uuid4()),
            context=context,
            image=image,
        )
