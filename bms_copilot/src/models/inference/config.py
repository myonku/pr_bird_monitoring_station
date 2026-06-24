from __future__ import annotations

from pathlib import Path

from msgspec import Struct, field

from src.models.inference.common import FrameworkKind, ModelTier, TaskType, lane_key
from src.models.inference.workflow import InferenceModelCandidateSpec


def _default_standard_candidates() -> list[InferenceModelCandidateSpec]:
    return [
        InferenceModelCandidateSpec(
            candidate_id="server_frcnn_r50_det",
            file_name="detection_standard_server_frcnn_r50_det.pth",
            task=TaskType.DETECTION,
            framework=FrameworkKind.PYTORCH,
            model_name="fasterrcnn_resnet50_fpn",
            format="custom",
            input_size=(640, 640),
            score_threshold=0.25,
            nms_iou_threshold=0.45,
            topk=1,
        ),
        InferenceModelCandidateSpec(
            candidate_id="server_yolo_m",
            file_name="detection_standard_server_yolo_m.pt",
            task=TaskType.DETECTION,
            framework=FrameworkKind.YOLO,
            model_name="yolo11m",
            format="custom",
            input_size=(640, 640),
            score_threshold=0.25,
            nms_iou_threshold=0.45,
            topk=1,
        ),
        InferenceModelCandidateSpec(
            candidate_id="server_yolo11m_cls",
            file_name="classification_standard_server_yolo11m_cls.pt",
            task=TaskType.CLASSIFICATION,
            framework=FrameworkKind.YOLO,
            model_name="yolo11m-cls",
            format="custom",
            input_size=(224, 224),
            score_threshold=0.0,
            nms_iou_threshold=0.0,
            topk=5,
        ),
        InferenceModelCandidateSpec(
            candidate_id="server_convnext_cls",
            file_name="classification_standard_server_convnext_cls.pth",
            task=TaskType.CLASSIFICATION,
            framework=FrameworkKind.PYTORCH,
            model_name="convnext_base",
            format="custom",
            input_size=(224, 224),
            score_threshold=0.0,
            nms_iou_threshold=0.0,
            topk=5,
        ),
    ]


def _resolve_path(base_dir: Path, value: str) -> str:
    path = Path(value)
    if not path.is_absolute():
        path = base_dir / path
    return str(path.resolve())


class InferenceConfig(Struct, kw_only=True):
    """data_worker 启动时强制加载的标准级模型包配置。"""

    required: bool = True
    root_dir: str = "model_pack"
    detection_dir: str = ""
    classification_dir: str = ""
    label_dir: str = "model_pack"
    detection_label_file_name: str = ""
    classification_label_file_name: str = "labels.txt"
    standard_candidates: list[InferenceModelCandidateSpec] = field(
        default_factory=_default_standard_candidates
    )
    notes: str = ""

    def normalized(self, *, base_dir: str | Path = ".") -> "InferenceConfig":
        base = Path(base_dir).resolve()
        if not self.required:
            raise ValueError("inference.required must be true")

        root_dir = _resolve_path(base, self.root_dir or "model_pack")
        detection_dir = self.detection_dir.strip() or str(
            Path(root_dir) / lane_key(TaskType.DETECTION, ModelTier.STANDARD)
        )
        classification_dir = self.classification_dir.strip() or str(
            Path(root_dir) / lane_key(TaskType.CLASSIFICATION, ModelTier.STANDARD)
        )
        label_dir = _resolve_path(base, self.label_dir or "model_pack")

        candidates = list(self.standard_candidates)
        if not candidates:
            raise ValueError("standard_candidates config is empty")
        if len(candidates) < 4:
            raise ValueError("standard_candidates must provide at least 4 entries")

        return InferenceConfig(
            required=True,
            root_dir=root_dir,
            detection_dir=_resolve_path(base, detection_dir),
            classification_dir=_resolve_path(base, classification_dir),
            label_dir=label_dir,
            detection_label_file_name=self.detection_label_file_name.strip(),
            classification_label_file_name=self.classification_label_file_name.strip()
            or "labels.txt",
            standard_candidates=candidates,
            notes=self.notes.strip(),
        )
