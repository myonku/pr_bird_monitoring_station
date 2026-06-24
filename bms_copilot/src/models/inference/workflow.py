from dataclasses import dataclass, field
import time
from typing import Any, Literal

from src.models.inference.common import ArtifactFormat, FrameworkKind, ModelTier, TaskType


def now_ms() -> int:
    return int(time.time() * 1000)


@dataclass(slots=True)
class InferenceImagePayload:
    image_id: str
    bytes_data: bytes
    format: str = "jpg"
    width: int | None = None
    height: int | None = None
    checksum_sha256: str | None = None


@dataclass(slots=True)
class InferenceModelCandidateSpec:
    candidate_id: str
    file_name: str
    task: TaskType
    framework: FrameworkKind
    model_name: str
    format: ArtifactFormat = "custom"
    input_size: tuple[int, int] = (640, 640)
    score_threshold: float = 0.25
    nms_iou_threshold: float = 0.45
    topk: int = 1


@dataclass(slots=True)
class InferenceModelArtifact:
    artifact_id: str
    candidate_id: str
    task: TaskType
    tier: ModelTier
    framework: FrameworkKind
    model_name: str
    format: ArtifactFormat
    model_version: str
    artifact_path: str
    labels: list[str] = field(default_factory=list)
    input_size: tuple[int, int] = (640, 640)
    score_threshold: float = 0.25
    nms_iou_threshold: float = 0.45
    topk: int = 5
    checksum_sha256: str | None = None


@dataclass(slots=True)
class InferenceModelContract:
    contract_version: str
    package_version: str
    exported_at_ms: int
    exported_by: str
    detection: InferenceModelArtifact
    classification: InferenceModelArtifact
    notes: str = ""


@dataclass(slots=True)
class LoadedInferenceBundle:
    contract: InferenceModelContract
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
    model_signature: str | None = None


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
    model_signature: str | None = None


@dataclass(slots=True)
class TwoStageInferenceResult:
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
    crop_applied: bool = False
    crop_box: dict[str, float] | None = None
    detector_model_version: str | None = None
    classifier_model_version: str | None = None
    detector_model_signature: str | None = None
    classifier_model_signature: str | None = None
    reason: str | None = None