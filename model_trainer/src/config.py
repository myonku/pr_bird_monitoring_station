from __future__ import annotations

import json
import tomllib
from dataclasses import asdict, dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any


class ModelTier(StrEnum):
    LIGHTWEIGHT = "lightweight"
    STANDARD = "standard"


class FrameworkKind(StrEnum):
    YOLO = "yolo"
    PYTORCH = "pytorch"
    CUSTOM = "custom"


class TaskType(StrEnum):
    DETECTION = "detection"
    CLASSIFICATION = "classification"


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
            raise ValueError(f"{name} out of range: {value}, expected [{min_v}, {max_v}]")

    @staticmethod
    def _validate_float(name: str, value: float, min_v: float, max_v: float) -> None:
        if not (min_v <= value <= max_v):
            raise ValueError(f"{name} out of range: {value}, expected [{min_v}, {max_v}]")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class DeploymentPathConfig:
    """训练产物路径路由，支持手动固定部署路径。"""

    edge_detection_model_path: Path | None = None
    edge_classification_model_path: Path | None = None
    server_detection_model_path: Path | None = None
    server_classification_model_path: Path | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "edge_detection_model_path": str(self.edge_detection_model_path)
            if self.edge_detection_model_path
            else None,
            "edge_classification_model_path": str(self.edge_classification_model_path)
            if self.edge_classification_model_path
            else None,
            "server_detection_model_path": str(self.server_detection_model_path)
            if self.server_detection_model_path
            else None,
            "server_classification_model_path": str(self.server_classification_model_path)
            if self.server_classification_model_path
            else None,
        }


@dataclass(slots=True)
class DatasetContract:
    """数据集契约：仅定义统一元信息，不绑定具体目录结构。"""

    dataset_id: str
    root: Path
    task: TaskType
    metadata_path: Path | None = None
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["root"] = str(self.root)
        payload["task"] = self.task.value
        if self.metadata_path is not None:
            payload["metadata_path"] = str(self.metadata_path)
        return payload


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
    project_name: str
    experiment_name: str
    output_root: Path = Path("output_models")
    logs_root: Path = Path("logs")
    training: TrainingCommonConfig = field(default_factory=TrainingCommonConfig)
    deployment: DeploymentPathConfig = field(default_factory=DeploymentPathConfig)
    dataset: DatasetContract | None = None
    candidates: list[ModelCandidate] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "project_name": self.project_name,
            "experiment_name": self.experiment_name,
            "output_root": str(self.output_root),
            "logs_root": str(self.logs_root),
            "training": self.training.to_dict(),
            "deployment": self.deployment.to_dict(),
            "dataset": self.dataset.to_dict() if self.dataset else None,
            "candidates": [candidate.to_dict() for candidate in self.candidates],
        }


def load_pipeline_config(path: Path) -> PipelineConfig:
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

    deployment_payload = payload.get("deployment", {})
    deployment = DeploymentPathConfig(
        edge_detection_model_path=Path(deployment_payload["edge_detection_model_path"])
        if deployment_payload.get("edge_detection_model_path")
        else None,
        edge_classification_model_path=Path(
            deployment_payload["edge_classification_model_path"]
        )
        if deployment_payload.get("edge_classification_model_path")
        else None,
        server_detection_model_path=Path(deployment_payload["server_detection_model_path"])
        if deployment_payload.get("server_detection_model_path")
        else None,
        server_classification_model_path=Path(
            deployment_payload["server_classification_model_path"]
        )
        if deployment_payload.get("server_classification_model_path")
        else None,
    )

    dataset_payload = payload.get("dataset")
    dataset = None
    if dataset_payload:
        dataset = DatasetContract(
            dataset_id=dataset_payload["dataset_id"],
            root=Path(dataset_payload["root"]),
            task=TaskType(dataset_payload["task"]),
            metadata_path=Path(dataset_payload["metadata_path"])
            if dataset_payload.get("metadata_path")
            else None,
            notes=dataset_payload.get("notes", ""),
        )

    candidates = [
        ModelCandidate(
            candidate_id=item["candidate_id"],
            framework=FrameworkKind(item["framework"]),
            model_name=item["model_name"],
            tier=ModelTier(item["tier"]),
            task=TaskType(item["task"]),
            train_params=item.get("train_params", {}),
            export_formats=item.get("export_formats", ["onnx"]),
        )
        for item in payload.get("candidates", [])
    ]

    return PipelineConfig(
        project_name=payload["project_name"],
        experiment_name=payload["experiment_name"],
        output_root=Path(payload.get("output_root", "output_models")),
        logs_root=Path(payload.get("logs_root", "logs")),
        training=training,
        deployment=deployment,
        dataset=dataset,
        candidates=candidates,
    )


def load_pipeline_from_settings_toml(path: Path) -> PipelineConfig:
    data = tomllib.loads(path.read_text(encoding="utf-8"))

    pipeline_tbl = data.get("pipeline", {})
    training_tbl = data.get("training", {})
    deployment_tbl = data.get("deployment", {})
    dataset_tbl = data.get("dataset", {})
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

    deployment = DeploymentPathConfig(
        edge_detection_model_path=Path(str(deployment_tbl["edge_detection_model_path"]))
        if deployment_tbl.get("edge_detection_model_path")
        else None,
        edge_classification_model_path=Path(
            str(deployment_tbl["edge_classification_model_path"])
        )
        if deployment_tbl.get("edge_classification_model_path")
        else None,
        server_detection_model_path=Path(str(deployment_tbl["server_detection_model_path"]))
        if deployment_tbl.get("server_detection_model_path")
        else None,
        server_classification_model_path=Path(
            str(deployment_tbl["server_classification_model_path"])
        )
        if deployment_tbl.get("server_classification_model_path")
        else None,
    )

    dataset = None
    if dataset_tbl:
        dataset = DatasetContract(
            dataset_id=str(dataset_tbl.get("dataset_id", "placeholder_dataset")),
            root=Path(str(dataset_tbl.get("root", "dataset"))),
            task=TaskType(str(dataset_tbl.get("task", TaskType.DETECTION.value))),
            metadata_path=Path(str(dataset_tbl["metadata_path"]))
            if dataset_tbl.get("metadata_path")
            else None,
            notes=str(dataset_tbl.get("notes", "")),
        )

    candidates = [
        ModelCandidate(
            candidate_id=str(item["candidate_id"]),
            framework=FrameworkKind(str(item["framework"])),
            model_name=str(item["model_name"]),
            tier=ModelTier(str(item["tier"])),
            task=TaskType(str(item["task"])),
            train_params=dict(item.get("train_params", {})),
            export_formats=list(item.get("export_formats", ["onnx"])),
        )
        for item in candidates_tbl
    ]

    return PipelineConfig(
        project_name=str(pipeline_tbl.get("project_name", "bird_monitoring_station")),
        experiment_name=str(pipeline_tbl.get("experiment_name", "baseline_dual_tier")),
        output_root=Path(str(pipeline_tbl.get("output_root", "output_models"))),
        logs_root=Path(str(pipeline_tbl.get("logs_root", "logs"))),
        training=training,
        deployment=deployment,
        dataset=dataset,
        candidates=candidates,
    )


def build_default_pipeline_config() -> PipelineConfig:
    return PipelineConfig(
        project_name="bird_model_delivery_tool",
        experiment_name="baseline_dual_tier",
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
        deployment=DeploymentPathConfig(
            edge_detection_model_path=None,
            edge_classification_model_path=None,
            server_detection_model_path=None,
            server_classification_model_path=None,
        ),
        dataset=DatasetContract(
            dataset_id="placeholder_dataset",
            root=Path("dataset"),
            task=TaskType.DETECTION,
            notes="PIR trigger + IR camera scenario, pending unified dataset schema",
        ),
        candidates=[
            ModelCandidate(
                candidate_id="edge_yolo_n",
                framework=FrameworkKind.YOLO,
                model_name="yolo11n",
                tier=ModelTier.LIGHTWEIGHT,
                task=TaskType.DETECTION,
                train_params={"epochs": 50, "imgsz": 640},
                export_formats=["onnx", "tflite"],
            ),
            ModelCandidate(
                candidate_id="server_yolo_m",
                framework=FrameworkKind.YOLO,
                model_name="yolo11m",
                tier=ModelTier.STANDARD,
                task=TaskType.DETECTION,
                train_params={"epochs": 80, "imgsz": 640},
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
