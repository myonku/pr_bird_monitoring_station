import hashlib
import time
from collections import deque
from typing import Any

from src.iface.workflow_interface import (
    ICaptureModule,
    IMotionSensor,
    ITemperatureHumiditySensor,
)
from src.ignitor.camera_module import (
    ICameraController,
    MockCameraController,
    PiCameraController,
)
from src.ignitor.environment_module import MockTemperatureHumiditySensor
from src.ignitor.sensor_module import MockMotionSensor, PIRMotionSensor
from src.models.workflow.workflow import CaptureContext, ImagePayload


class CaptureRateLimiter:
    """抓拍频率限制器：先应用最短触发间隔，再应用窗口限频。"""

    def __init__(
        self,
        window_sec: float,
        max_images: int,
        min_trigger_interval_sec: float = 1.0,
    ) -> None:
        self.min_trigger_interval_sec = max(float(min_trigger_interval_sec), 1.0)
        self.max_images = int(max_images)
        self.window_sec = max(float(window_sec), 0.0)
        if self.max_images > 0 and self.window_sec > 0:
            self.window_sec = max(
                self.window_sec,
                self.min_trigger_interval_sec * self.max_images,
            )
        self._history: deque[float] = deque()
        self._last_capture_at: float | None = None

    @property
    def enabled(self) -> bool:
        return self.window_sec > 0 and self.max_images > 0

    def _evict_expired(self, now: float) -> None:
        if not self.enabled:
            self._history.clear()
            return
        while self._history and (now - self._history[0]) >= self.window_sec:
            self._history.popleft()

    def acquire(self) -> None:
        while True:
            now = time.monotonic()

            if self._last_capture_at is not None:
                interval_wait_sec = self.min_trigger_interval_sec - (
                    now - self._last_capture_at
                )
                if interval_wait_sec > 0:
                    time.sleep(interval_wait_sec)
                    continue

            if not self.enabled:
                self._last_capture_at = now
                return

            self._evict_expired(now)

            if len(self._history) < self.max_images:
                self._history.append(now)
                self._last_capture_at = now
                return

            wait_sec = self.window_sec - (now - self._history[0])
            if wait_sec <= 0:
                continue
            time.sleep(wait_sec)

    def snapshot(self) -> dict[str, Any]:
        return {
            "enabled": self.enabled,
            "window_sec": self.window_sec,
            "max_images": self.max_images if self.enabled else 0,
            "min_trigger_interval_sec": self.min_trigger_interval_sec,
        }


class SensorCameraCaptureModule(ICaptureModule):
    """捕拍编排器：仅在此处协同 sensor 与 camera。"""

    def __init__(
        self,
        device_id: str,
        device_name: str,
        location_name: str,
        sensor: IMotionSensor,
        camera: ICameraController,
        image_format: str = "jpg",
        capture_cooldown_sec: float = 0.0,
        sensor_wait_timeout_sec: float | None = None,
        capture_min_trigger_interval_sec: float = 1.0,
        capture_rate_window_sec: float = 0.0,
        capture_rate_max_images: int = 0,
        environment_sensor: ITemperatureHumiditySensor | None = None,
    ) -> None:
        self.device_id = device_id
        self.device_name = device_name or "unknown"
        self.location_name = location_name or "unknown"
        self._sensor = sensor
        self._camera = camera
        self._environment_sensor = environment_sensor or MockTemperatureHumiditySensor()
        self.image_format = image_format
        self.capture_cooldown_sec = capture_cooldown_sec
        self.sensor_wait_timeout_sec = sensor_wait_timeout_sec
        self._rate_limiter = CaptureRateLimiter(
            window_sec=capture_rate_window_sec,
            max_images=capture_rate_max_images,
            min_trigger_interval_sec=capture_min_trigger_interval_sec,
        )

    def close(self) -> None:
        for component in (
            getattr(self, "_camera", None),
            getattr(self, "_sensor", None),
            getattr(self, "_environment_sensor", None),
        ):
            if component is None:
                continue
            close_fn = getattr(component, "close", None)
            if callable(close_fn):
                try:
                    close_fn()
                except Exception:
                    pass

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass

    def wait_and_capture(
        self,
        timeout_sec: float | None = None,
    ) -> tuple[CaptureContext, ImagePayload]:
        wait_timeout = (
            timeout_sec if timeout_sec is not None else self.sensor_wait_timeout_sec
        )
        motion_detected = self._sensor.wait_for_motion(timeout_sec=wait_timeout)
        if not motion_detected:
            raise TimeoutError("capture_wait_timeout")

        self._rate_limiter.acquire()

        image_bytes, width, height = self._camera.capture(self.image_format)
        environment_snapshot = self._environment_sensor.read_snapshot()

        if self.capture_cooldown_sec > 0:
            time.sleep(self.capture_cooldown_sec)

        sensor_snapshot = dict(self._sensor.snapshot())
        sensor_snapshot["rate_limit"] = self._rate_limiter.snapshot()

        context = CaptureContext(
            device_id=self.device_id,
            device_name=self.device_name,
            location_name=self.location_name,
            trigger_type="motion",
            sensor_snapshot=sensor_snapshot,
            environment_snapshot=environment_snapshot,
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


class MockCaptureModule(SensorCameraCaptureModule):
    """开发模式捕拍模块：mock sensor + mock camera。"""

    def __init__(
        self,
        device_id: str,
        device_name: str = "unknown",
        location_name: str = "unknown",
        image_format: str = "jpg",
        image_width: int = 1920,
        image_height: int = 1080,
        capture_min_trigger_interval_sec: float = 1.0,
        capture_rate_window_sec: float = 0.0,
        capture_rate_max_images: int = 0,
    ) -> None:
        super().__init__(
            device_id=device_id,
            device_name=device_name,
            location_name=location_name,
            sensor=MockMotionSensor(),
            camera=MockCameraController(
                image_width=image_width,
                image_height=image_height,
            ),
            image_format=image_format,
            capture_cooldown_sec=0.0,
            sensor_wait_timeout_sec=None,
            capture_min_trigger_interval_sec=capture_min_trigger_interval_sec,
            capture_rate_window_sec=capture_rate_window_sec,
            capture_rate_max_images=capture_rate_max_images,
        )


class PIRCameraCaptureModule(SensorCameraCaptureModule):
    """树莓派模式捕拍模块：PIR 触发 + 相机抓拍。"""

    def __init__(
        self,
        device_id: str,
        device_name: str = "unknown",
        location_name: str = "unknown",
        pir_gpio_pin: int = 17,
        image_format: str = "jpg",
        image_width: int = 1920,
        image_height: int = 1080,
        capture_cooldown_sec: float = 0.1,
        pir_wait_timeout_sec: float | None = None,
        capture_min_trigger_interval_sec: float = 1.0,
        capture_rate_window_sec: float = 0.0,
        capture_rate_max_images: int = 0,
    ) -> None:
        super().__init__(
            device_id=device_id,
            device_name=device_name,
            location_name=location_name,
            sensor=PIRMotionSensor(pir_gpio_pin=pir_gpio_pin),
            camera=PiCameraController(
                image_width=image_width,
                image_height=image_height,
            ),
            image_format=image_format,
            capture_cooldown_sec=capture_cooldown_sec,
            sensor_wait_timeout_sec=pir_wait_timeout_sec,
            capture_min_trigger_interval_sec=capture_min_trigger_interval_sec,
            capture_rate_window_sec=capture_rate_window_sec,
            capture_rate_max_images=capture_rate_max_images,
        )
