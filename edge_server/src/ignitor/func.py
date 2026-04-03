from src.iface.workflow_interface import ICaptureModule
from src.models.sys.config import CaptureConfig
from src.ignitor.capture_module import MockCaptureModule, PIRCameraCaptureModule
from src.iface.workflow_interface import ICaptureModule
from src.models.sys.config import CaptureConfig


def build_capture_module(
    capture_cfg: CaptureConfig,
    device_id: str,
) -> ICaptureModule:
    """根据配置构建捕拍模块实例。"""

    if capture_cfg.mode == "pir":
        return PIRCameraCaptureModule(
            device_id=device_id,
            pir_gpio_pin=capture_cfg.pir_gpio_pin,
            image_format=capture_cfg.image_format,
            image_width=capture_cfg.image_width,
            image_height=capture_cfg.image_height,
            capture_cooldown_sec=capture_cfg.capture_cooldown_sec,
            pir_wait_timeout_sec=capture_cfg.pir_wait_timeout_sec,
        )

    return MockCaptureModule(
        device_id=device_id,
        image_format=capture_cfg.image_format,
        image_width=capture_cfg.image_width,
        image_height=capture_cfg.image_height,
    )
