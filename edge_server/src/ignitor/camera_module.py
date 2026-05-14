import importlib
import io
from collections.abc import Iterable
from typing import Any, Callable, cast
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
        self.camera_num: int | None = None
        self._camera: Any = None

        try:
            picamera2_cls: Any = getattr(
                importlib.import_module("picamera2"), "Picamera2"
            )
        except ImportError as exc:
            raise ModuleNotFoundError(
                "PIR capture mode requires picamera2 on Raspberry Pi"
            ) from exc

        camera_infos = self._discover_camera_infos(picamera2_cls)
        if camera_infos:
            print(
                "[edge] picamera2_camera_info "
                + " | ".join(
                    self._format_camera_info(camera_info, index)
                    for index, camera_info in enumerate(camera_infos)
                ),
                flush=True,
            )

        camera_nums = self._discover_camera_nums(camera_infos)
        if not camera_nums:
            raise RuntimeError("No Picamera2 camera detected on this device")

        init_errors: list[str] = []
        for camera_num in camera_nums:
            camera: Any = None
            try:
                camera = picamera2_cls(camera_num=camera_num)
                camera_cfg = camera.create_still_configuration(
                    main={"size": (self.image_width, self.image_height)}
                )
                camera.configure(camera_cfg)
                camera.start()
                self._camera = camera
                self.camera_num = camera_num
                print(
                    "[edge] picamera2_camera_selected "
                    f"camera_num={camera_num} "
                    f"image_width={self.image_width} "
                    f"image_height={self.image_height}",
                    flush=True,
                )
                return
            except Exception as exc:
                init_errors.append(f"camera_num={camera_num}: {exc}")
                self._close_component(camera)

        raise RuntimeError(
            "No usable Picamera2 camera could be initialized: "
            + "; ".join(init_errors)
        )

    @staticmethod
    def _discover_camera_infos(picamera2_cls: Any) -> list[Any]:
        global_camera_info = cast(
            Callable[[], Iterable[Any]],
            getattr(picamera2_cls, "global_camera_info", None),
        )
        if not callable(global_camera_info):
            raise RuntimeError("picamera2 is missing global_camera_info()")

        return list(global_camera_info())

    @staticmethod
    def _discover_camera_nums(camera_infos: list[Any]) -> list[int]:

        camera_nums: list[int] = []
        for index, camera_info in enumerate(camera_infos):
            if isinstance(camera_info, dict):
                raw_camera_num = camera_info.get("Num", index)
            else:
                raw_camera_num = index

            try:
                camera_nums.append(int(raw_camera_num))
            except (TypeError, ValueError):
                continue
        return camera_nums

    @staticmethod
    def _format_camera_info(camera_info: Any, fallback_num: int) -> str:
        if isinstance(camera_info, dict):
            raw_camera_num = camera_info.get("Num", fallback_num)
            camera_id = str(camera_info.get("Id", "unknown"))
            camera_model = str(camera_info.get("Model", "unknown"))
        else:
            raw_camera_num = fallback_num
            camera_id = "unknown"
            camera_model = type(camera_info).__name__

        try:
            camera_num = int(raw_camera_num)
        except (TypeError, ValueError):
            camera_num = fallback_num

        return f"camera_num={camera_num} camera_id={camera_id} camera_model={camera_model}"

    @staticmethod
    def _close_component(component: Any | None) -> None:
        if component is None:
            return
        close_fn = getattr(component, "close", None)
        if callable(close_fn):
            try:
                close_fn()
            except Exception:
                pass

    def capture(self, image_format: str) -> tuple[bytes, int, int]:
        output = io.BytesIO()
        save_format = "JPEG" if image_format.lower() in {"jpg", "jpeg"} else "PNG"
        self._camera.capture_file(output, format=save_format)
        image_bytes = output.getvalue()
        with Image.open(io.BytesIO(image_bytes)) as image:
            width, height = image.size
        return image_bytes, width, height

    def close(self) -> None:
        self._close_component(getattr(self, "_camera", None))
