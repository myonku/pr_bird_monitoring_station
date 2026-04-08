import importlib
import time
from typing import Any

from src.iface.workflow_interface import IMotionSensor


class MockMotionSensor(IMotionSensor):
    """开发模式触发器；可选短等待后恒定触发。"""

    def wait_for_motion(self, timeout_sec: float | None = None) -> bool:
        if timeout_sec is not None and timeout_sec > 0:
            time.sleep(min(timeout_sec, 0.05))
        return True

    def snapshot(self) -> dict[str, Any]:
        return {"capture_mode": "mock"}


class PIRMotionSensor(IMotionSensor):
    """树莓派 PIR 传感器适配器。"""

    def __init__(self, pir_gpio_pin: int) -> None:
        self.pir_gpio_pin = pir_gpio_pin
        try:
            button_cls = getattr(importlib.import_module("gpiozero"), "Button")
        except ImportError as exc:
            raise ModuleNotFoundError(
                "PIR capture mode requires gpiozero on Raspberry Pi"
            ) from exc

        self._sensor: Any = button_cls(self.pir_gpio_pin, pull_up=False)

    def wait_for_motion(self, timeout_sec: float | None = None) -> bool:
        deadline = None
        if timeout_sec is not None:
            deadline = time.monotonic() + max(float(timeout_sec), 0.0)

        while True:
            if bool(self._sensor.is_active):
                return True
            if deadline is not None and time.monotonic() >= deadline:
                return False
            time.sleep(0.02)

    def snapshot(self) -> dict[str, Any]:
        return {
            "capture_mode": "pir",
            "pir_gpio_pin": self.pir_gpio_pin,
            "trigger_mode": "active_high",
        }

    def close(self) -> None:
        if hasattr(self, "_sensor") and self._sensor is not None:
            close_fn = getattr(self._sensor, "close", None)
            if callable(close_fn):
                try:
                    close_fn()
                except Exception:
                    pass
