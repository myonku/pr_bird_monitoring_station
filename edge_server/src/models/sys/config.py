from dataclasses import dataclass
from typing import Literal

from src.models.workflow.workflow import ModelPackLocator


ArtifactTask = Literal["detection", "classification"]
ArtifactFormat = Literal["onnx", "tflite", "torchscript", "openvino", "custom"]


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
    cpu_high_watermark: float = 0.85
    memory_high_watermark: float = 0.90


@dataclass(slots=True)
class RuntimeConfig:
    device_id: str
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
    image_format: str = "jpg"
    image_width: int = 1920
    image_height: int = 1080


@dataclass(slots=True)
class EdgeServerConfig:
    runtime: RuntimeConfig
    auth: AuthConfig
    capture: CaptureConfig
    upload_http: UploadHttpConfig
    decision_policy: DecisionPolicyConfig
    model_pack: ModelPackLocator
