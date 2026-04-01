from __future__ import annotations

import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, cast

from src.models.models import LightweightModelCandidateSpec, ModelPackLocator


ArtifactTask = Literal["detection", "classification"]
ArtifactFormat = Literal["onnx", "tflite", "torchscript", "openvino", "custom"]


def _parse_task(value: str) -> ArtifactTask:
    if value not in {"detection", "classification"}:
        raise ValueError(f"unsupported task: {value}")
    return cast(ArtifactTask, value)


def _parse_format(value: str) -> ArtifactFormat:
    if value not in {"onnx", "tflite", "torchscript", "openvino", "custom"}:
        raise ValueError(f"unsupported format: {value}")
    return cast(ArtifactFormat, value)


def _parse_input_size(payload: Any, default: tuple[int, int]) -> tuple[int, int]:
    if not isinstance(payload, (list, tuple)) or len(payload) != 2:
        return default
    return int(payload[0]), int(payload[1])


def _default_lightweight_candidates() -> list[dict[str, Any]]:
    return [
        {
            "candidate_id": "edge_frcnn_mbv3_det",
            "file_name": "detection_lightweight_edge_frcnn_mbv3_det.pth",
            "task": "detection",
            "framework": "pytorch",
            "model_name": "fasterrcnn_mobilenet_v3_large_320_fpn",
            "format": "custom",
            "input_size": [640, 640],
            "score_threshold": 0.25,
            "nms_iou_threshold": 0.45,
            "topk": 1,
        },
        {
            "candidate_id": "edge_yolo_n",
            "file_name": "detection_lightweight_edge_yolo_n.onnx",
            "task": "detection",
            "framework": "yolo",
            "model_name": "yolo11n",
            "format": "onnx",
            "input_size": [640, 640],
            "score_threshold": 0.25,
            "nms_iou_threshold": 0.45,
            "topk": 1,
        },
        {
            "candidate_id": "edge_mobilenet_cls",
            "file_name": "classification_lightweight_edge_mobilenet_cls.pth",
            "task": "classification",
            "framework": "pytorch",
            "model_name": "mobilenet_v3_large",
            "format": "custom",
            "input_size": [224, 224],
            "score_threshold": 0.0,
            "nms_iou_threshold": 0.0,
            "topk": 5,
        },
        {
            "candidate_id": "edge_yolo11n_cls",
            "file_name": "classification_lightweight_edge_yolo11n_cls.onnx",
            "task": "classification",
            "framework": "yolo",
            "model_name": "yolo11n-cls",
            "format": "onnx",
            "input_size": [224, 224],
            "score_threshold": 0.0,
            "nms_iou_threshold": 0.0,
            "topk": 5,
        },
    ]


@dataclass(slots=True)
class UploadHttpConfig:
    upload_url: str
    healthcheck_url: str
    timeout_sec: float = 3.0
    auth_token: str | None = None


@dataclass(slots=True)
class DecisionPolicyConfig:
    enable_local_inference: bool = True
    confidence_threshold: float = 0.6
    high_load_skip_inference: bool = False


@dataclass(slots=True)
class RuntimeConfig:
    device_id: str
    spool_dir: str = "data/spool"
    sync_interval_sec: float = 3.0
    sync_batch_size: int = 20


@dataclass(slots=True)
class EdgeServerConfig:
    runtime: RuntimeConfig
    upload_http: UploadHttpConfig
    decision_policy: DecisionPolicyConfig
    model_pack: ModelPackLocator


def _resolve_path(base_dir: Path, value: str) -> str:
    path = Path(value)
    if not path.is_absolute():
        path = base_dir / path
    return str(path.resolve())


def load_edge_config(settings_path: str | Path) -> EdgeServerConfig:
    path = Path(settings_path)
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    base_dir = path.parent.resolve()

    runtime_tbl = data.get("runtime", {})
    upload_tbl = data.get("upload_http", {})
    decision_tbl = data.get("decision_policy", {})
    model_pack_tbl = data.get("model_pack", {})
    candidate_tbls = data.get("model_pack_lightweight_candidates", [])

    runtime = RuntimeConfig(
        device_id=str(runtime_tbl.get("device_id", "edge_device_001")),
        spool_dir=str(runtime_tbl.get("spool_dir", "data/spool")),
        sync_interval_sec=float(runtime_tbl.get("sync_interval_sec", 3.0)),
        sync_batch_size=int(runtime_tbl.get("sync_batch_size", 20)),
    )

    upload = UploadHttpConfig(
        upload_url=str(upload_tbl.get("upload_url", "http://127.0.0.1:8000/v1/edge/events")),
        healthcheck_url=str(upload_tbl.get("healthcheck_url", "http://127.0.0.1:8000/health")),
        timeout_sec=float(upload_tbl.get("timeout_sec", 3.0)),
        auth_token=str(upload_tbl["auth_token"]) if upload_tbl.get("auth_token") else None,
    )

    decision = DecisionPolicyConfig(
        enable_local_inference=bool(decision_tbl.get("enable_local_inference", True)),
        confidence_threshold=float(decision_tbl.get("confidence_threshold", 0.6)),
        high_load_skip_inference=bool(decision_tbl.get("high_load_skip_inference", False)),
    )

    root_dir = _resolve_path(
        base_dir,
        str(model_pack_tbl.get("root_dir", "model_pack")),
    )
    detection_dir = _resolve_path(
        base_dir,
        str(model_pack_tbl.get("detection_dir", "model_pack/detection")),
    )
    classification_dir = _resolve_path(
        base_dir,
        str(model_pack_tbl.get("classification_dir", "model_pack/classification")),
    )
    label_dir = _resolve_path(
        base_dir,
        str(model_pack_tbl.get("label_dir", "model_pack")),
    )
    detection_label_file_name = str(
        model_pack_tbl.get("detection_label_file_name", "")
    ).strip()
    classification_label_file_name = str(
        model_pack_tbl.get("classification_label_file_name", "labels.txt")
    ).strip()

    rows = (
        candidate_tbls
        if isinstance(candidate_tbls, list) and candidate_tbls
        else _default_lightweight_candidates()
    )
    candidates: list[LightweightModelCandidateSpec] = []
    for index, row in enumerate(rows, start=1):
        if not isinstance(row, dict):
            raise ValueError(
                "model_pack_lightweight_candidates entries must be table objects"
            )

        task = _parse_task(str(row.get("task", "")))
        default_input = (640, 640) if task == "detection" else (224, 224)
        default_topk = 1 if task == "detection" else 5
        default_score = 0.25 if task == "detection" else 0.0
        default_nms = 0.45 if task == "detection" else 0.0

        file_name = str(row.get("file_name", "")).strip()
        if not file_name:
            raise ValueError(
                f"model_pack_lightweight_candidates[{index}] missing file_name"
            )

        candidates.append(
            LightweightModelCandidateSpec(
                candidate_id=str(row.get("candidate_id", f"lite_candidate_{index}")),
                file_name=file_name,
                task=task,
                framework=str(row.get("framework", "")).strip(),
                model_name=str(row.get("model_name", "")).strip(),
                format=_parse_format(str(row.get("format", "custom"))),
                input_size=_parse_input_size(row.get("input_size"), default_input),
                score_threshold=float(row.get("score_threshold", default_score)),
                nms_iou_threshold=float(row.get("nms_iou_threshold", default_nms)),
                topk=int(row.get("topk", default_topk)),
            )
        )

    if len(candidates) < 4:
        raise ValueError(
            "model_pack_lightweight_candidates must provide at least 4 entries"
        )

    model_pack = ModelPackLocator(
        root_dir=root_dir,
        detection_dir=detection_dir,
        classification_dir=classification_dir,
        label_dir=label_dir,
        detection_label_file_name=detection_label_file_name,
        classification_label_file_name=classification_label_file_name,
        lightweight_candidates=candidates,
    )

    return EdgeServerConfig(
        runtime=runtime,
        upload_http=upload,
        decision_policy=decision,
        model_pack=model_pack,
    )