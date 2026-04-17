import json
import tomllib
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from src.models.dataset_model import DatasetContract
from src.models.common import ModelTier, FrameworkKind, LabelPolicy, TaskType


def _resolve_path(base_dir: Path, raw: str | Path) -> Path:
    path = Path(raw)
    if path.is_absolute():
        return path
    return (base_dir / path).resolve()


def _resolve_optional_path(base_dir: Path, raw: str | Path | None) -> Path | None:
    if raw is None:
        return None
    return _resolve_path(base_dir, raw)


def _normalize_export_formats(raw_formats: list[str] | None) -> list[str]:
    # 统一禁用 tflite 导出，避免在 Python 3.13 环境触发不可安装依赖链。
    formats = raw_formats or ["onnx"]
    filtered: list[str] = []
    for fmt in formats:
        key = str(fmt).strip().lower()
        if not key or key == "tflite":
            continue
        if key not in filtered:
            filtered.append(key)
    return filtered or ["onnx"]


def _normalize_candidate_train_params(
    *,
    base_dir: Path,
    framework: FrameworkKind,
    model_name: str,
    raw_params: dict[str, Any] | None,
) -> dict[str, Any]:
    params = dict(raw_params or {})
    if framework != FrameworkKind.YOLO:
        return params

    pretrained = params.get("pretrained")
    if pretrained in (None, ""):
        params["pretrained"] = str(_resolve_path(base_dir, f"weights/{model_name}.pt"))
        return params

    if isinstance(pretrained, Path):
        params["pretrained"] = str(_resolve_path(base_dir, pretrained))
        return params

    if isinstance(pretrained, str):
        value = pretrained.strip()
        if value.startswith(
            (
                "http://",
                "https://",
                "rtsp://",
                "rtmp://",
                "tcp://",
                "ul://",
            )
        ):
            params["pretrained"] = value
        else:
            params["pretrained"] = str(_resolve_path(base_dir, value))
    return params


@dataclass(slots=True)
class TrainingCommonConfig:
    """训练通用配置，支持范围校验。"""

    seed: int = 42
    epochs: int = 50
    batch_size: int = 16
    image_size: int = 640
    learning_rate: float = 1e-3
    weight_decay: float = 1e-4
    num_workers: int = 4
    amp: bool = True
    early_stop_patience: int = 20

    def __post_init__(self) -> None:
        self._validate_int("seed", self.seed, 0, 2_147_483_647)
        self._validate_int("epochs", self.epochs, 1, 1000)
        self._validate_int("batch_size", self.batch_size, 1, 1024)
        self._validate_int("image_size", self.image_size, 64, 4096)
        self._validate_float("learning_rate", self.learning_rate, 1e-7, 10.0)
        self._validate_float("weight_decay", self.weight_decay, 0.0, 1.0)
        self._validate_int("num_workers", self.num_workers, 0, 128)
        self._validate_int("early_stop_patience", self.early_stop_patience, 0, 200)

    @staticmethod
    def _validate_int(name: str, value: int, min_v: int, max_v: int) -> None:
        if not (min_v <= value <= max_v):
            raise ValueError(
                f"{name} out of range: {value}, expected [{min_v}, {max_v}]"
            )

    @staticmethod
    def _validate_float(name: str, value: float, min_v: float, max_v: float) -> None:
        if not (min_v <= value <= max_v):
            raise ValueError(
                f"{name} out of range: {value}, expected [{min_v}, {max_v}]"
            )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class CropGenerationConfig:
    """基于检测模型生成分类裁切数据集的配置。"""

    enabled: bool = False
    framework: FrameworkKind = FrameworkKind.YOLO
    detector_model_path: Path = Path(
        "output_models/detection_lite/latest_detection_lightweight_edge_yolo_n.onnx"
    )
    label_file_name: str = "class.txt"
    source_root: Path = Path("dataset/classification_source")
    output_root: Path = Path("dataset/classification_cropped")
    score_threshold: float = 0.25
    max_crops_per_image: int = 1
    max_selection_candidates: int = 20
    min_box_area_ratio: float = 0.02
    max_box_area_ratio: float = 0.90
    min_box_edge_margin_ratio: float = 0.0
    max_images_per_class: int = 0
    show_progress: bool = True
    progress_interval: int = 1000

    def __post_init__(self) -> None:
        if not (0.0 <= self.score_threshold <= 1.0):
            raise ValueError("score_threshold must be within [0.0, 1.0]")
        if self.max_crops_per_image < 1:
            raise ValueError("max_crops_per_image must be >= 1")
        if self.max_selection_candidates < 1:
            raise ValueError("max_selection_candidates must be >= 1")
        if not (0.0 <= self.min_box_area_ratio <= 1.0):
            raise ValueError("min_box_area_ratio must be within [0.0, 1.0]")
        if not (0.0 <= self.max_box_area_ratio <= 1.0):
            raise ValueError("max_box_area_ratio must be within [0.0, 1.0]")
        if self.max_box_area_ratio < self.min_box_area_ratio:
            raise ValueError(
                "max_box_area_ratio must be >= min_box_area_ratio"
            )
        if not (0.0 <= self.min_box_edge_margin_ratio < 0.5):
            raise ValueError(
                "min_box_edge_margin_ratio must be within [0.0, 0.5)"
            )
        if self.max_images_per_class < 0:
            raise ValueError("max_images_per_class must be >= 0")
        if self.progress_interval < 1:
            raise ValueError("progress_interval must be >= 1")
        if not self.label_file_name.strip():
            raise ValueError("label_file_name must not be empty")

    def to_dict(self) -> dict[str, Any]:
        return {
            "enabled": self.enabled,
            "framework": self.framework.value,
            "detector_model_path": str(self.detector_model_path),
            "label_file_name": self.label_file_name,
            "source_root": str(self.source_root),
            "output_root": str(self.output_root),
            "score_threshold": self.score_threshold,
            "max_crops_per_image": self.max_crops_per_image,
            "max_selection_candidates": self.max_selection_candidates,
            "min_box_area_ratio": self.min_box_area_ratio,
            "max_box_area_ratio": self.max_box_area_ratio,
            "min_box_edge_margin_ratio": self.min_box_edge_margin_ratio,
            "max_images_per_class": self.max_images_per_class,
            "show_progress": self.show_progress,
            "progress_interval": self.progress_interval,
        }


@dataclass(slots=True)
class ModelCandidate:
    """候选模型规格：供训练后端统一消费。"""

    candidate_id: str
    framework: FrameworkKind
    model_name: str
    tier: ModelTier
    task: TaskType
    train_params: dict[str, Any] = field(default_factory=dict)
    export_formats: list[str] = field(default_factory=lambda: ["onnx"])

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["framework"] = self.framework.value
        payload["tier"] = self.tier.value
        payload["task"] = self.task.value
        return payload


@dataclass(slots=True)
class PipelineConfig:
    """整体实验配置：训练通用配置 + 数据集契约 + 模型候选列表。"""

    output_root: Path = Path("output_models")
    logs_root: Path = Path("logs")
    training: TrainingCommonConfig = field(default_factory=TrainingCommonConfig)
    detection_dataset: DatasetContract | None = None
    classification_dataset: DatasetContract | None = None
    crop_generation: CropGenerationConfig = field(default_factory=CropGenerationConfig)
    candidates: list[ModelCandidate] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "output_root": str(self.output_root),
            "logs_root": str(self.logs_root),
            "training": self.training.to_dict(),
            "detection_dataset": (
                self.detection_dataset.to_dict() if self.detection_dataset else None
            ),
            "classification_dataset": (
                self.classification_dataset.to_dict()
                if self.classification_dataset
                else None
            ),
            "crop_generation": self.crop_generation.to_dict(),
            "candidates": [candidate.to_dict() for candidate in self.candidates],
        }


def _parse_dataset_contract(payload: dict[str, Any], base_dir: Path) -> DatasetContract:
    return DatasetContract(
        dataset_id=payload["dataset_id"],
        root=_resolve_path(base_dir, payload["root"]),
        task=TaskType(payload["task"]),
        label_policy=LabelPolicy(payload.get("label_policy", LabelPolicy.AS_IS.value)),
        label_file_name=str(payload.get("label_file_name", "class.txt")),
        metadata_path=_resolve_optional_path(base_dir, payload.get("metadata_path")),
        notes=payload.get("notes", ""),
    )


def load_pipeline_config(path: Path) -> PipelineConfig:
    base_dir = path.parent.resolve()
    payload = json.loads(path.read_text(encoding="utf-8"))

    training_payload = payload.get("training", {})
    training = TrainingCommonConfig(
        seed=int(training_payload.get("seed", 42)),
        epochs=int(training_payload.get("epochs", 50)),
        batch_size=int(training_payload.get("batch_size", 16)),
        image_size=int(training_payload.get("image_size", 640)),
        learning_rate=float(training_payload.get("learning_rate", 1e-3)),
        weight_decay=float(training_payload.get("weight_decay", 1e-4)),
        num_workers=int(training_payload.get("num_workers", 4)),
        amp=bool(training_payload.get("amp", True)),
        early_stop_patience=int(training_payload.get("early_stop_patience", 20)),
    )

    detection_dataset_payload = payload.get("detection_dataset")
    detection_dataset = (
        _parse_dataset_contract(detection_dataset_payload, base_dir=base_dir)
        if detection_dataset_payload
        else None
    )

    classification_dataset_payload = payload.get("classification_dataset")
    classification_dataset = (
        _parse_dataset_contract(classification_dataset_payload, base_dir=base_dir)
        if classification_dataset_payload
        else None
    )

    crop_payload = payload.get("crop_generation", {})
    crop_generation = CropGenerationConfig(
        enabled=bool(crop_payload.get("enabled", False)),
        framework=FrameworkKind(
            crop_payload.get("framework", FrameworkKind.YOLO.value)
        ),
        detector_model_path=_resolve_path(
            base_dir,
            crop_payload.get(
                "detector_model_path",
                "output_models/detection_lite/latest_detection_lightweight_edge_yolo_n.onnx",
            ),
        ),
        label_file_name=str(crop_payload.get("label_file_name", "class.txt")),
        source_root=_resolve_path(
            base_dir,
            crop_payload.get("source_root", "dataset/classification_source"),
        ),
        output_root=_resolve_path(
            base_dir,
            crop_payload.get("output_root", "dataset/classification_cropped"),
        ),
        score_threshold=float(crop_payload.get("score_threshold", 0.25)),
        max_crops_per_image=int(crop_payload.get("max_crops_per_image", 1)),
        max_selection_candidates=int(crop_payload.get("max_selection_candidates", 20)),
        min_box_area_ratio=float(crop_payload.get("min_box_area_ratio", 0.02)),
        max_box_area_ratio=float(crop_payload.get("max_box_area_ratio", 0.90)),
        min_box_edge_margin_ratio=float(
            crop_payload.get("min_box_edge_margin_ratio", 0.0)
        ),
        max_images_per_class=int(crop_payload.get("max_images_per_class", 0)),
        show_progress=bool(crop_payload.get("show_progress", True)),
        progress_interval=int(crop_payload.get("progress_interval", 1000)),
    )

    candidates: list[ModelCandidate] = []
    for item in payload.get("candidates", []):
        framework = FrameworkKind(item["framework"])
        model_name = item["model_name"]
        candidates.append(
            ModelCandidate(
                candidate_id=item["candidate_id"],
                framework=framework,
                model_name=model_name,
                tier=ModelTier(item["tier"]),
                task=TaskType(item["task"]),
                train_params=_normalize_candidate_train_params(
                    base_dir=base_dir,
                    framework=framework,
                    model_name=model_name,
                    raw_params=item.get("train_params", {}),
                ),
                export_formats=_normalize_export_formats(
                    item.get("export_formats", ["onnx"])
                ),
            )
        )

    return PipelineConfig(
        output_root=_resolve_path(base_dir, payload.get("output_root", "output_models")),
        logs_root=_resolve_path(base_dir, payload.get("logs_root", "logs")),
        training=training,
        detection_dataset=detection_dataset,
        classification_dataset=classification_dataset,
        crop_generation=crop_generation,
        candidates=candidates,
    )


def load_pipeline_from_settings_toml(path: Path) -> PipelineConfig:
    base_dir = path.parent.resolve()
    data = tomllib.loads(path.read_text(encoding="utf-8"))

    pipeline_tbl = data.get("pipeline", {})
    training_tbl = data.get("training", {})
    detection_dataset_tbl = data.get("detection_dataset", {})
    classification_dataset_tbl = data.get("classification_dataset", {})
    crop_tbl = data.get("crop_generation", {})
    candidates_tbl = data.get("candidates", [])

    training = TrainingCommonConfig(
        seed=int(training_tbl.get("seed", 42)),
        epochs=int(training_tbl.get("epochs", 50)),
        batch_size=int(training_tbl.get("batch_size", 16)),
        image_size=int(training_tbl.get("image_size", 640)),
        learning_rate=float(training_tbl.get("learning_rate", 1e-3)),
        weight_decay=float(training_tbl.get("weight_decay", 1e-4)),
        num_workers=int(training_tbl.get("num_workers", 4)),
        amp=bool(training_tbl.get("amp", True)),
        early_stop_patience=int(training_tbl.get("early_stop_patience", 20)),
    )

    detection_dataset = None
    if detection_dataset_tbl:
        detection_dataset = DatasetContract(
            dataset_id=str(detection_dataset_tbl.get("dataset_id", "det_dataset")),
            root=_resolve_path(
                base_dir,
                str(detection_dataset_tbl.get("root", "dataset/detection_source")),
            ),
            task=TaskType.DETECTION,
            label_policy=LabelPolicy(
                str(
                    detection_dataset_tbl.get(
                        "label_policy", LabelPolicy.SINGLE_CLASS_BIRD.value
                    )
                )
            ),
            label_file_name=str(detection_dataset_tbl.get("label_file_name", "class.txt")),
            metadata_path=_resolve_optional_path(
                base_dir,
                str(detection_dataset_tbl["metadata_path"])
                if detection_dataset_tbl.get("metadata_path")
                else None,
            ),
            notes=str(detection_dataset_tbl.get("notes", "")),
        )

    classification_dataset = None
    if classification_dataset_tbl:
        classification_dataset = DatasetContract(
            dataset_id=str(
                classification_dataset_tbl.get("dataset_id", "cls_dataset_cropped")
            ),
            root=_resolve_path(
                base_dir,
                str(
                    classification_dataset_tbl.get(
                        "root", "dataset/classification_cropped"
                    )
                )
            ),
            task=TaskType.CLASSIFICATION,
            label_policy=LabelPolicy(
                str(
                    classification_dataset_tbl.get(
                        "label_policy", LabelPolicy.SPECIES_CLASSIFICATION.value
                    )
                )
            ),
            label_file_name=str(
                classification_dataset_tbl.get("label_file_name", "class.txt")
            ),
            metadata_path=_resolve_optional_path(
                base_dir,
                str(classification_dataset_tbl["metadata_path"])
                if classification_dataset_tbl.get("metadata_path")
                else None,
            ),
            notes=str(classification_dataset_tbl.get("notes", "")),
        )

    crop_generation = CropGenerationConfig(
        enabled=bool(crop_tbl.get("enabled", False)),
        framework=FrameworkKind(
            str(crop_tbl.get("framework", FrameworkKind.YOLO.value))
        ),
        detector_model_path=_resolve_path(
            base_dir,
            str(
                crop_tbl.get(
                    "detector_model_path",
                    "output_models/detection_lite/latest_detection_lightweight_edge_yolo_n.onnx",
                )
            ),
        ),
        label_file_name=str(crop_tbl.get("label_file_name", "class.txt")),
        source_root=_resolve_path(
            base_dir,
            str(crop_tbl.get("source_root", "dataset/classification_source")),
        ),
        output_root=_resolve_path(
            base_dir,
            str(crop_tbl.get("output_root", "dataset/classification_cropped")),
        ),
        score_threshold=float(crop_tbl.get("score_threshold", 0.25)),
        max_crops_per_image=int(crop_tbl.get("max_crops_per_image", 1)),
        max_selection_candidates=int(crop_tbl.get("max_selection_candidates", 20)),
        min_box_area_ratio=float(crop_tbl.get("min_box_area_ratio", 0.02)),
        max_box_area_ratio=float(crop_tbl.get("max_box_area_ratio", 0.90)),
        min_box_edge_margin_ratio=float(crop_tbl.get("min_box_edge_margin_ratio", 0.0)),
        max_images_per_class=int(crop_tbl.get("max_images_per_class", 0)),
        show_progress=bool(crop_tbl.get("show_progress", True)),
        progress_interval=int(crop_tbl.get("progress_interval", 1000)),
    )

    candidates: list[ModelCandidate] = []
    for item in candidates_tbl:
        framework = FrameworkKind(str(item["framework"]))
        model_name = str(item["model_name"])
        candidates.append(
            ModelCandidate(
                candidate_id=str(item["candidate_id"]),
                framework=framework,
                model_name=model_name,
                tier=ModelTier(str(item["tier"])),
                task=TaskType(str(item["task"])),
                train_params=_normalize_candidate_train_params(
                    base_dir=base_dir,
                    framework=framework,
                    model_name=model_name,
                    raw_params=dict(item.get("train_params", {})),
                ),
                export_formats=_normalize_export_formats(
                    list(item.get("export_formats", ["onnx"]))
                ),
            )
        )

    return PipelineConfig(
        output_root=_resolve_path(base_dir, str(pipeline_tbl.get("output_root", "output_models"))),
        logs_root=_resolve_path(base_dir, str(pipeline_tbl.get("logs_root", "logs"))),
        training=training,
        detection_dataset=detection_dataset,
        classification_dataset=classification_dataset,
        crop_generation=crop_generation,
        candidates=candidates,
    )


def build_default_pipeline_config() -> PipelineConfig:
    return PipelineConfig(
        training=TrainingCommonConfig(
            seed=42,
            epochs=50,
            batch_size=16,
            image_size=640,
            learning_rate=1e-3,
            weight_decay=1e-4,
            num_workers=4,
            amp=True,
            early_stop_patience=20,
        ),
        detection_dataset=DatasetContract(
            dataset_id="detection_source",
            root=Path("CUB_200_2011/bird_detection_dataset"),
            task=TaskType.DETECTION,
            label_policy=LabelPolicy.SINGLE_CLASS_BIRD,
            notes="Use converted CUB unified detection layout (bird_detection_dataset), collapse classes to 'bird'",
        ),
        classification_dataset=DatasetContract(
            dataset_id="classification_cropped",
            root=Path("dataset/classification_cropped"),
            task=TaskType.CLASSIFICATION,
            label_policy=LabelPolicy.SPECIES_CLASSIFICATION,
            label_file_name="class.txt",
            notes="Use detector-cropped images with species labels",
        ),
        crop_generation=CropGenerationConfig(
            enabled=True,
            framework=FrameworkKind.YOLO,
            detector_model_path=Path(
                "output_models/detection_lite/latest_detection_lightweight_edge_yolo_n.onnx"
            ),
            label_file_name="class.txt",
            source_root=Path("dataset/classification_source"),
            output_root=Path("dataset/classification_cropped"),
            score_threshold=0.25,
            max_crops_per_image=1,
            max_selection_candidates=20,
            min_box_area_ratio=0.02,
            max_box_area_ratio=0.90,
            min_box_edge_margin_ratio=0.0,
            max_images_per_class=0,
            show_progress=True,
            progress_interval=1000,
        ),
        candidates=[
            ModelCandidate(
                candidate_id="edge_yolo_n",
                framework=FrameworkKind.YOLO,
                model_name="yolo11n",
                tier=ModelTier.LIGHTWEIGHT,
                task=TaskType.DETECTION,
                train_params={
                    "epochs": 50,
                    "imgsz": 640,
                    "pretrained": "weights/yolo11n.pt",
                },
                export_formats=["onnx"],
            ),
            ModelCandidate(
                candidate_id="server_yolo_m",
                framework=FrameworkKind.YOLO,
                model_name="yolo11m",
                tier=ModelTier.STANDARD,
                task=TaskType.DETECTION,
                train_params={
                    "epochs": 80,
                    "imgsz": 640,
                    "pretrained": "weights/yolo11m.pt",
                },
                export_formats=["onnx"],
            ),
            ModelCandidate(
                candidate_id="edge_mobilenet_cls",
                framework=FrameworkKind.PYTORCH,
                model_name="mobilenet_v3_large",
                tier=ModelTier.LIGHTWEIGHT,
                task=TaskType.CLASSIFICATION,
                train_params={"epochs": 40, "batch_size": 64},
                export_formats=["onnx", "torchscript"],
            ),
            ModelCandidate(
                candidate_id="server_convnext_cls",
                framework=FrameworkKind.PYTORCH,
                model_name="convnext_base",
                tier=ModelTier.STANDARD,
                task=TaskType.CLASSIFICATION,
                train_params={"epochs": 60, "batch_size": 32},
                export_formats=["onnx", "torchscript"],
            ),
        ],
    )
