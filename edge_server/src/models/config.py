from __future__ import annotations

import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, cast

from src.models.models import EdgeModelContract, ModelArtifactContract


ArtifactTask = Literal["detection", "classification"]
ArtifactTier = Literal["lightweight", "standard"]
ArtifactFormat = Literal["onnx", "tflite", "torchscript", "openvino", "custom"]


def _parse_task(value: str) -> ArtifactTask:
    if value not in {"detection", "classification"}:
        raise ValueError(f"unsupported task: {value}")
    return cast(ArtifactTask, value)


def _parse_tier(value: str) -> ArtifactTier:
    if value not in {"lightweight", "standard"}:
        raise ValueError(f"unsupported tier: {value}")
    return cast(ArtifactTier, value)


def _parse_format(value: str) -> ArtifactFormat:
    if value not in {"onnx", "tflite", "torchscript", "openvino", "custom"}:
        raise ValueError(f"unsupported format: {value}")
    return cast(ArtifactFormat, value)


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
    model_contract: EdgeModelContract


def _parse_artifact(payload: dict, expected_task: str) -> ModelArtifactContract:
    parsed_task = _parse_task(str(payload["task"]))
    parsed_tier = _parse_tier(str(payload["tier"]))
    parsed_format = _parse_format(str(payload["format"]))

    artifact = ModelArtifactContract(
        artifact_id=str(payload["artifact_id"]),
        task=parsed_task,
        tier=parsed_tier,
        framework=str(payload["framework"]),
        model_name=str(payload["model_name"]),
        format=parsed_format,
        model_version=str(payload["model_version"]),
        artifact_path=str(payload["artifact_path"]),
        labels=list(payload.get("labels", [])),
        input_size=tuple(payload.get("input_size", [640, 640])),
        score_threshold=float(payload.get("score_threshold", 0.25)),
        nms_iou_threshold=float(payload.get("nms_iou_threshold", 0.45)),
        topk=int(payload.get("topk", 5)),
        checksum_sha256=str(payload["checksum_sha256"])
        if payload.get("checksum_sha256")
        else None,
    )
    if artifact.task != expected_task:
        raise ValueError(f"artifact task mismatch: expected {expected_task}, got {artifact.task}")
    return artifact


def load_edge_config(settings_path: str | Path) -> EdgeServerConfig:
    path = Path(settings_path)
    data = tomllib.loads(path.read_text(encoding="utf-8"))

    runtime_tbl = data.get("runtime", {})
    upload_tbl = data.get("upload_http", {})
    decision_tbl = data.get("decision_policy", {})
    contract_tbl = data.get("model_contract", {})
    detector_tbl = data.get("model_contract_detection", {})
    classifier_tbl = data.get("model_contract_classification", {})

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

    detection = _parse_artifact(detector_tbl, expected_task="detection")
    classification = _parse_artifact(classifier_tbl, expected_task="classification")
    contract = EdgeModelContract(
        contract_version=str(contract_tbl.get("contract_version", "1.0.0")),
        package_version=str(contract_tbl.get("package_version", "edge-default")),
        exported_at_ms=int(contract_tbl.get("exported_at_ms", 0)),
        exported_by=str(contract_tbl.get("exported_by", "model_trainer")),
        detection=detection,
        classification=classification,
        notes=str(contract_tbl.get("notes", "")),
    )

    return EdgeServerConfig(
        runtime=runtime,
        upload_http=upload,
        decision_policy=decision,
        model_contract=contract,
    )