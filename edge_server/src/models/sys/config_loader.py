from pathlib import Path
from typing import Any, Literal, cast
from urllib.parse import urlparse


from src.models.workflow.workflow import (
    LightweightModelCandidateSpec,
    ModelPackLocator,
)
from src.models.sys.config import (
    ArtifactFormat,
    ArtifactTask,
    AuthConfig,
    CaptureConfig,
    DecisionPolicyConfig,
    EdgeServerConfig,
    RuntimeLogConfig,
    RuntimeLogStage,
    RuntimeMode,
    RuntimeConfig,
    UploadHttpConfig,
)


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


def _resolve_path(base_dir: Path, value: str) -> str:
    path = Path(value)
    if not path.is_absolute():
        path = base_dir / path
    return str(path.resolve())


def _normalize_backend_base_url(value: str, *, default: str) -> str:
    raw = str(value).strip() if value is not None else ""
    if not raw:
        raw = default
    parsed = urlparse(raw)
    if not parsed.scheme or not parsed.netloc:
        raise ValueError(f"invalid backend base url: {raw}")
    return f"{parsed.scheme}://{parsed.netloc}".rstrip("/")


def _normalize_http_path(value: str | None, *, default: str) -> str:
    raw = str(value).strip() if value is not None else ""
    if not raw:
        raw = default
    parsed = urlparse(raw)
    if parsed.scheme and parsed.netloc:
        raw = parsed.path or "/"
    if not raw.startswith("/"):
        raw = f"/{raw}"
    if len(raw) > 1 and raw.endswith("/"):
        raw = raw.rstrip("/")
    return raw


def _normalize_display_name(value: Any, *, default: str = "unknown") -> str:
    raw = str(value).strip() if value is not None else ""
    return raw or default


def _parse_runtime_log_stages(payload: Any) -> list[RuntimeLogStage]:
    default_stages: list[RuntimeLogStage] = [
        "startup",
        "capture",
        "decision",
        "inference",
        "delivery",
        "sync",
        "auth",
    ]

    if payload is None:
        return default_stages

    raw_items: list[str]
    if isinstance(payload, str):
        raw_items = [part.strip().lower() for part in payload.split(",")]
    elif isinstance(payload, list):
        raw_items = [str(item).strip().lower() for item in payload]
    else:
        return default_stages

    allowed = {
        "startup",
        "capture",
        "decision",
        "inference",
        "delivery",
        "sync",
        "auth",
        "all",
    }
    stages: list[RuntimeLogStage] = []
    for item in raw_items:
        if not item:
            continue
        if item not in allowed:
            raise ValueError(f"unsupported runtime_log stage: {item}")
        stages.append(cast(RuntimeLogStage, item))

    if not stages:
        return default_stages
    return stages


def load_edge_config(
    config_data: dict[str, Any],
    *,
    base_dir: str | Path = ".",
) -> EdgeServerConfig:
    if not isinstance(config_data, dict):
        raise ValueError("config_data must be a dict loaded from settings")

    data = config_data
    base_dir = Path(base_dir).resolve()

    runtime_tbl = data.get("runtime", {})
    auth_tbl = data.get("auth", {})
    capture_tbl = data.get("capture", {})
    runtime_log_tbl = data.get("runtime_log", {})
    upload_tbl = data.get("upload_http", {})
    decision_tbl = data.get("decision_policy", {})
    model_pack_tbl = data.get("model_pack", {})
    candidate_tbls = data.get("model_pack_lightweight_candidates", [])

    legacy_spool_dir = str(runtime_tbl.get("spool_dir", "data"))
    default_spool_db_path = str(Path(legacy_spool_dir) / "edge_spool.sqlite3")
    run_mode_raw = str(runtime_tbl.get("run_mode", "full_development")).strip().lower()
    if run_mode_raw in {
        "prod",
        "live",
        "production",
        "full",
        "integrated",
        "full_development",
        "full-development",
        "full_dev",
        "e2e",
    }:
        run_mode_raw = "full_development"
    if run_mode_raw in {"dev", "local", "test"}:
        run_mode_raw = "development"
    if run_mode_raw in {
        "no_auth",
        "no-auth",
        "noauth",
        "without_auth",
        "without-auth",
        "unauth",
        "unauthenticated",
    }:
        run_mode_raw = "no_auth"
    if run_mode_raw not in {"full_development", "development", "no_auth"}:
        raise ValueError(f"unsupported runtime run_mode: {run_mode_raw}")

    runtime = RuntimeConfig(
        device_id=str(runtime_tbl.get("device_id", "edge_device_001")),
        device_name=_normalize_display_name(runtime_tbl.get("device_name")),
        location_name=_normalize_display_name(runtime_tbl.get("location_name")),
        run_mode=cast(RuntimeMode, run_mode_raw),
        spool_db_path=_resolve_path(
            base_dir,
            str(runtime_tbl.get("spool_db_path", default_spool_db_path)),
        ),
        sync_interval_sec=float(runtime_tbl.get("sync_interval_sec", 3.0)),
        sync_batch_size=int(runtime_tbl.get("sync_batch_size", 20)),
    )

    auth = AuthConfig(
        secret_key_dir=_resolve_path(
            base_dir,
            str(auth_tbl.get("secret_key_dir", "secret_keys")),
        ),
        active_key_id=str(auth_tbl.get("active_key_id", "")).strip(),
        auth_state_db_path=_resolve_path(
            base_dir,
            str(auth_tbl.get("auth_state_db_path", "data/edge_auth.sqlite3")),
        ),
    )

    capture_mode = str(capture_tbl.get("mode", "mock")).strip().lower()
    if capture_mode not in {"mock", "pir"}:
        raise ValueError(f"unsupported capture mode: {capture_mode}")

    pir_wait_timeout_raw = capture_tbl.get("pir_wait_timeout_sec")
    capture_rate_window_sec = float(capture_tbl.get("capture_rate_window_sec", 0.0))
    capture_rate_max_images = int(capture_tbl.get("capture_rate_max_images", 0))
    if capture_rate_window_sec < 0:
        raise ValueError("capture_rate_window_sec must be >= 0")
    if capture_rate_max_images < 0:
        raise ValueError("capture_rate_max_images must be >= 0")

    capture = CaptureConfig(
        mode=cast(Literal["mock", "pir"], capture_mode),
        pir_gpio_pin=int(capture_tbl.get("pir_gpio_pin", 17)),
        pir_wait_timeout_sec=(
            float(pir_wait_timeout_raw) if pir_wait_timeout_raw is not None else None
        ),
        capture_cooldown_sec=float(capture_tbl.get("capture_cooldown_sec", 0.1)),
        capture_rate_window_sec=capture_rate_window_sec,
        capture_rate_max_images=capture_rate_max_images,
        image_format=str(capture_tbl.get("image_format", "jpg")).strip().lower(),
        image_width=int(capture_tbl.get("image_width", 1920)),
        image_height=int(capture_tbl.get("image_height", 1080)),
    )

    cpu_high_watermark = float(decision_tbl.get("cpu_high_watermark", 0.85))
    memory_high_watermark = float(decision_tbl.get("memory_high_watermark", 0.90))
    if not (0.0 < cpu_high_watermark <= 1.0):
        raise ValueError("cpu_high_watermark must be in (0, 1]")
    if not (0.0 < memory_high_watermark <= 1.0):
        raise ValueError("memory_high_watermark must be in (0, 1]")

    upload = UploadHttpConfig(
        base_backend_url=_normalize_backend_base_url(
            str(upload_tbl.get("base_backend_url", "")),
            default="http://127.0.0.1:8000",
        ),
        upload_path=_normalize_http_path(
            str(upload_tbl.get("upload_path", "")).strip(),
            default="/v1/edge/events",
        ),
        auth_path=_normalize_http_path(
            str(upload_tbl.get("auth_path", "")).strip(),
            default="/v1/edge/auth",
        ),
        healthcheck_path=_normalize_http_path(
            str(upload_tbl.get("healthcheck_path", "")).strip(),
            default="/health",
        ),
        timeout_sec=float(upload_tbl.get("timeout_sec", 3.0)),
    )

    decision = DecisionPolicyConfig(
        enable_local_inference=bool(decision_tbl.get("enable_local_inference", True)),
        confidence_threshold=float(decision_tbl.get("confidence_threshold", 0.6)),
        high_load_skip_inference=bool(
            decision_tbl.get("high_load_skip_inference", False)
        ),
        cpu_high_watermark=cpu_high_watermark,
        memory_high_watermark=memory_high_watermark,
    )

    runtime_log = RuntimeLogConfig(
        enabled=bool(runtime_log_tbl.get("enabled", True)),
        include_timestamp=bool(runtime_log_tbl.get("include_timestamp", True)),
        stages=_parse_runtime_log_stages(runtime_log_tbl.get("stages")),
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
        auth=auth,
        capture=capture,
        upload_http=upload,
        decision_policy=decision,
        runtime_log=runtime_log,
        model_pack=model_pack,
    )
