import importlib
import io
from typing import Any
from PIL import Image

from src.iface.workflow_interface import ICameraController


class MockCameraController(ICameraController):
    """开发模式相机；按配置生成灰度图。"""

    def __init__(self, image_width: int, image_height: int) -> None:
        self.image_width = image_width
        self.image_height = image_height

    def capture(self, image_format: str) -> tuple[bytes, int, int]:
        image = Image.new("RGB", (self.image_width, self.image_height), (128, 128, 128))
        output = io.BytesIO()
        save_format = "JPEG" if image_format.lower() in {"jpg", "jpeg"} else "PNG"
        image.save(output, format=save_format)
        return output.getvalue(), self.image_width, self.image_height


class PiCameraController(ICameraController):
    """树莓派 Picamera2 适配器。"""

    def __init__(self, image_width: int, image_height: int) -> None:
        self.image_width = image_width
        self.image_height = image_height

        try:
            picamera2_cls = getattr(importlib.import_module("picamera2"), "Picamera2")
        except ImportError as exc:
            raise ModuleNotFoundError(
                "PIR capture mode requires picamera2 on Raspberry Pi"
            ) from exc

        self._camera: Any = picamera2_cls()
        camera_cfg = self._camera.create_still_configuration(
            main={"size": (self.image_width, self.image_height)}
        )
        self._camera.configure(camera_cfg)
        self._camera.start()

    def capture(self, image_format: str) -> tuple[bytes, int, int]:
        output = io.BytesIO()
        save_format = "JPEG" if image_format.lower() in {"jpg", "jpeg"} else "PNG"
        self._camera.capture_file(output, format=save_format)
        image_bytes = output.getvalue()
        with Image.open(io.BytesIO(image_bytes)) as image:
            width, height = image.size
        return image_bytes, width, height

    def close(self) -> None:
        if hasattr(self, "_camera") and self._camera is not None:
            try:
                self._camera.close()
            except Exception:
                pass
