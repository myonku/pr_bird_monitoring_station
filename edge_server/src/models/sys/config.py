from dataclasses import dataclass
from typing import Literal

from src.models.workflow.workflow import ModelPackLocator


ArtifactTask = Literal["detection", "classification"]
ArtifactFormat = Literal["onnx", "tflite", "torchscript", "openvino", "custom"]
RuntimeMode = Literal["development", "no_auth", "full_development"]
RuntimeLogStage = Literal[
    "startup",
    "capture",
    "decision",
    "inference",
    "delivery",
    "sync",
    "auth",
    "all",
]


@dataclass(slots=True)
class UploadHttpConfig:
    base_backend_url: str
    upload_path: str = "/v1/edge/events"
    auth_path: str = "/v1/edge/auth"
    healthcheck_path: str = "/health"
    timeout_sec: float = 3.0

    @staticmethod
    def _normalize_path(path: str) -> str:
        normalized = path.strip()
        if not normalized:
            return "/"
        if not normalized.startswith("/"):
            normalized = f"/{normalized}"
        if len(normalized) > 1 and normalized.endswith("/"):
            normalized = normalized.rstrip("/")
        return normalized

    def build_url(self, path: str) -> str:
        base = self.base_backend_url.rstrip("/")
        return f"{base}{self._normalize_path(path)}"

    @property
    def upload_url(self) -> str:
        return self.build_url(self.upload_path)

    @property
    def healthcheck_url(self) -> str:
        return self.build_url(self.healthcheck_path)


@dataclass(slots=True)
class DecisionPolicyConfig:
    enable_local_inference: bool = True
    confidence_threshold: float = 0.6
    high_load_skip_inference: bool = False
    cpu_high_watermark: float = 0.85
    memory_high_watermark: float = 0.90


@dataclass(slots=True)
class RuntimeConfig:
    device_id: str
    device_name: str = "unknown"
    location_name: str = "unknown"
    run_mode: RuntimeMode = "full_development"
    spool_db_path: str = "data/edge_spool.sqlite3"
    sync_interval_sec: float = 3.0
    sync_batch_size: int = 20


@dataclass(slots=True)
class AuthConfig:
    secret_key_dir: str = "secret_keys"
    active_key_id: str = ""
    auth_state_db_path: str = "data/edge_auth.sqlite3"


@dataclass(slots=True)
class CaptureConfig:
    mode: Literal["mock", "pir"] = "mock"
    pir_gpio_pin: int = 17
    pir_wait_timeout_sec: float | None = None
    capture_cooldown_sec: float = 0.1
    capture_rate_window_sec: float = 0.0
    capture_rate_max_images: int = 0
    image_format: str = "jpg"
    image_width: int = 1920
    image_height: int = 1080


@dataclass(slots=True)
class RuntimeLogConfig:
    enabled: bool = True
    include_timestamp: bool = True
    stages: list[RuntimeLogStage] | None = None


@dataclass(slots=True)
class EdgeServerConfig:
    runtime: RuntimeConfig
    auth: AuthConfig
    capture: CaptureConfig
    upload_http: UploadHttpConfig
    decision_policy: DecisionPolicyConfig
    runtime_log: RuntimeLogConfig
    model_pack: ModelPackLocator
