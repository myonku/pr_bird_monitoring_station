import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Literal


def now_ms() -> int:
    return int(time.time() * 1000)


@dataclass(slots=True)
class DeviceInfo:
    device_id: str
    device_name: str = "unknown"
    location_name: str = "unknown"
    model: str = ""
    firmware_version: str = ""


@dataclass(slots=True)
class TemperatureHumiditySnapshot:
    temperature_c: float | None = None
    humidity_pct: int | None = None
    source: str = "pseudo_mock"
    sensor_snapshot: dict[str, Any] = field(default_factory=dict)
    captured_at_ms: int = field(default_factory=now_ms)


@dataclass(slots=True)
class CaptureContext:
    device_id: str
    device_name: str = "unknown"
    location_name: str = "unknown"
    trigger_type: Literal["motion", "scheduled", "manual"] = "motion"
    sensor_snapshot: dict[str, Any] = field(default_factory=dict)
    environment_snapshot: TemperatureHumiditySnapshot | None = None
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
class LightweightModelCandidateSpec:
    """边缘端 lightweight 候选模型配置（通过文件名映射）。"""

    candidate_id: str
    file_name: str
    task: Literal["detection", "classification"]
    framework: str
    model_name: str
    format: Literal["onnx", "tflite", "torchscript", "openvino", "custom"] = "custom"
    input_size: tuple[int, int] = (640, 640)
    score_threshold: float = 0.25
    nms_iou_threshold: float = 0.45
    topk: int = 1


@dataclass(slots=True)
class ModelPackLocator:
    """边缘端本地模型包目录配置（每个 task 目录仅保留一个模型文件）。"""

    root_dir: str
    detection_dir: str
    classification_dir: str
    label_dir: str
    detection_label_file_name: str = ""
    classification_label_file_name: str = "labels.txt"
    lightweight_candidates: list[LightweightModelCandidateSpec] = field(
        default_factory=list
    )


@dataclass(slots=True)
class ModelArtifactContract:
    """边缘端运行时的单模型元信息（由文件名与文件本身推导）。"""

    artifact_id: str
    candidate_id: str
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
    """边缘端运行时模型快照（由 model_pack 扫描后生成）。"""

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
    """单个检测框结果。坐标为相对值（0-1），相对于输入模型的预处理尺寸。
    推理模块负责根据 contract 的 input_size 进行坐标转换。"""

    label: str
    confidence: float
    x1: float
    y1: float
    x2: float
    y2: float


@dataclass(slots=True)
class DetectionResult:
    """检测结果。附带使用的模型版本和 signature 以便后续分析和追踪。"""

    success: bool
    boxes: list[DetectionBox] = field(default_factory=list)
    latency_ms: int | None = None
    reason: str | None = None
    model_signature: str | None = None


@dataclass(slots=True)
class ClassificationHit:
    """单个分类结果。"""

    label: str
    confidence: float


@dataclass(slots=True)
class ClassificationResult:
    """分类结果。附带使用的模型版本和 signature 以便后续分析和追踪。
    top1 和 topk 可选输出，视模型输出和推理模块实现而定。"""

    success: bool
    top1_label: str | None = None
    top1_confidence: float | None = None
    topk: list[ClassificationHit] = field(default_factory=list)
    latency_ms: int | None = None
    reason: str | None = None
    model_signature: str | None = None


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
    crop_applied: bool = False
    crop_box: dict[str, float] | None = None
    detector_model_version: str | None = None
    classifier_model_version: str | None = None
    detector_model_signature: str | None = None
    classifier_model_signature: str | None = None
    reason: str | None = None


@dataclass(slots=True)
class EdgeEvent:
    """边缘事件：一次完整的捕获 + 推理流程中的数据载荷和上下文信息。
    每个事件对应一次捕获触发，包含捕获上下文、图像数据、推理结果等。"""

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
