from src.iface.workflow_interface import ICaptureModule
from src.ignitor.capture_module import MockCaptureModule, PIRCameraCaptureModule
from src.models.sys.config import CaptureConfig


def build_capture_module(
    capture_cfg: CaptureConfig,
    device_id: str,
    device_name: str = "unknown",
    location_name: str = "unknown",
) -> ICaptureModule:
    """根据配置构建捕拍模块实例。"""

    if capture_cfg.mode == "pir":
        return PIRCameraCaptureModule(
            device_id=device_id,
            device_name=device_name,
            location_name=location_name,
            pir_gpio_pin=capture_cfg.pir_gpio_pin,
            image_format=capture_cfg.image_format,
            image_width=capture_cfg.image_width,
            image_height=capture_cfg.image_height,
            capture_cooldown_sec=capture_cfg.capture_cooldown_sec,
            pir_wait_timeout_sec=capture_cfg.pir_wait_timeout_sec,
            capture_min_trigger_interval_sec=capture_cfg.capture_min_trigger_interval_sec,
            capture_rate_window_sec=capture_cfg.capture_rate_window_sec,
            capture_rate_max_images=capture_cfg.capture_rate_max_images,
        )

    return MockCaptureModule(
        device_id=device_id,
        device_name=device_name,
        location_name=location_name,
        image_format=capture_cfg.image_format,
        image_width=capture_cfg.image_width,
        image_height=capture_cfg.image_height,
        capture_min_trigger_interval_sec=capture_cfg.capture_min_trigger_interval_sec,
        capture_rate_window_sec=capture_cfg.capture_rate_window_sec,
        capture_rate_max_images=capture_cfg.capture_rate_max_images,
    )
