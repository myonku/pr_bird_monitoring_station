import hashlib
import importlib
import io
import time
from typing import Any

from PIL import Image

from src.iface.workflow_interface import ICaptureModule
from src.models.workflow.workflow import CaptureContext, ImagePayload


class MockCaptureModule(ICaptureModule):
    """开发模式捕拍模块：生成灰度测试图，便于本地联调。"""

    def __init__(
        self,
        device_id: str,
        image_format: str = "jpg",
        image_width: int = 1920,
        image_height: int = 1080,
    ) -> None:
        self.device_id = device_id
        self.image_format = image_format
        self.image_width = image_width
        self.image_height = image_height

    def wait_and_capture(
        self,
        timeout_sec: float | None = None,
    ) -> tuple[CaptureContext, ImagePayload]:
        if timeout_sec is not None and timeout_sec > 0:
            time.sleep(min(timeout_sec, 0.05))

        image = Image.new("RGB", (self.image_width, self.image_height), (128, 128, 128))
        output = io.BytesIO()
        save_format = "JPEG" if self.image_format.lower() in {"jpg", "jpeg"} else "PNG"
        image.save(output, format=save_format)
        image_bytes = output.getvalue()

        context = CaptureContext(
            device_id=self.device_id,
            trigger_type="motion",
            sensor_snapshot={"capture_mode": "mock"},
        )
        payload = ImagePayload(
            image_id=f"img-{int(time.time() * 1000)}",
            bytes_data=image_bytes,
            format=self.image_format,
            width=self.image_width,
            height=self.image_height,
            checksum_sha256=hashlib.sha256(image_bytes).hexdigest(),
        )
        return context, payload


class PIRCameraCaptureModule(ICaptureModule):
    """树莓派模式捕拍模块：PIR 触发 + 相机抓拍。"""

    def __init__(
        self,
        device_id: str,
        pir_gpio_pin: int = 17,
        image_format: str = "jpg",
        image_width: int = 1920,
        image_height: int = 1080,
        capture_cooldown_sec: float = 0.1,
        pir_wait_timeout_sec: float | None = None,
    ) -> None:
        self.device_id = device_id
        self.pir_gpio_pin = pir_gpio_pin
        self.image_format = image_format
        self.image_width = image_width
        self.image_height = image_height
        self.capture_cooldown_sec = capture_cooldown_sec
        self.pir_wait_timeout_sec = pir_wait_timeout_sec

        try:
            MotionSensor = getattr(importlib.import_module("gpiozero"), "MotionSensor")
            Picamera2 = getattr(importlib.import_module("picamera2"), "Picamera2")
        except ImportError as exc:
            raise ModuleNotFoundError(
                "PIR capture mode requires gpiozero and picamera2 on Raspberry Pi"
            ) from exc

        self._sensor: Any = MotionSensor(self.pir_gpio_pin)
        self._camera: Any = Picamera2()
        camera_cfg = self._camera.create_still_configuration(
            main={"size": (self.image_width, self.image_height)}
        )
        self._camera.configure(camera_cfg)
        self._camera.start()

    def close(self) -> None:
        if hasattr(self, "_camera") and self._camera is not None:
            try:
                self._camera.close()
            except Exception:
                pass

    def __del__(self) -> None:
        self.close()

    def wait_and_capture(
        self,
        timeout_sec: float | None = None,
    ) -> tuple[CaptureContext, ImagePayload]:
        wait_timeout = timeout_sec if timeout_sec is not None else self.pir_wait_timeout_sec
        self._sensor.wait_for_motion(timeout=wait_timeout)

        if not self._sensor.motion_detected:
            raise TimeoutError("pir_wait_timeout")

        output = io.BytesIO()
        save_format = "JPEG" if self.image_format.lower() in {"jpg", "jpeg"} else "PNG"
        self._camera.capture_file(output, format=save_format)
        image_bytes = output.getvalue()

        with Image.open(io.BytesIO(image_bytes)) as image:
            width, height = image.size

        if self.capture_cooldown_sec > 0:
            time.sleep(self.capture_cooldown_sec)

        context = CaptureContext(
            device_id=self.device_id,
            trigger_type="motion",
            sensor_snapshot={
                "capture_mode": "pir",
                "pir_gpio_pin": self.pir_gpio_pin,
            },
        )
        payload = ImagePayload(
            image_id=f"img-{int(time.time() * 1000)}",
            bytes_data=image_bytes,
            format=self.image_format,
            width=width,
            height=height,
            checksum_sha256=hashlib.sha256(image_bytes).hexdigest(),
        )
        return context, payload
