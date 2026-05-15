import sys
from pathlib import Path
from unittest import TestCase, main
from unittest.mock import patch


EDGE_SERVER_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(EDGE_SERVER_ROOT))

from src.ignitor.capture_module import SensorCameraCaptureModule
from src.models.sys.config_loader import load_edge_config
from src.models.workflow.workflow import TemperatureHumiditySnapshot


class _AlwaysMotionSensor:
    def wait_for_motion(self, timeout_sec: float | None = None) -> bool:
        return True

    def snapshot(self) -> dict[str, object]:
        return {"motion": True}

    def close(self) -> None:
        return None


class _DummyCamera:
    def capture(self, image_format: str) -> tuple[bytes, int, int]:
        return b"img", 640, 480

    def close(self) -> None:
        return None


class _DummyEnvironmentSensor:
    def read_snapshot(self) -> TemperatureHumiditySnapshot:
        return TemperatureHumiditySnapshot(temperature_c=25.0, humidity_pct=60)

    def close(self) -> None:
        return None


class _VirtualClock:
    def __init__(self, start: float = 0.0) -> None:
        self._now = start
        self.sleep_calls: list[float] = []

    def monotonic(self) -> float:
        return self._now

    def sleep(self, sec: float) -> None:
        self.sleep_calls.append(sec)
        self._now += sec


class CaptureRateConstraintsTests(TestCase):
    def test_config_loader_enforces_min_interval_floor_and_adaptive_window(self) -> None:
        cfg = load_edge_config(
            {
                "capture": {
                    "capture_min_trigger_interval_sec": 0.2,
                    "capture_rate_window_sec": 2.0,
                    "capture_rate_max_images": 3,
                }
            },
            base_dir=EDGE_SERVER_ROOT,
        )

        self.assertEqual(cfg.capture.capture_min_trigger_interval_sec, 1.0)
        self.assertEqual(cfg.capture.capture_rate_window_sec, 3.0)
        self.assertEqual(cfg.capture.capture_rate_max_images, 3)

    def test_config_loader_keeps_window_disabled_when_rate_limit_not_enabled(self) -> None:
        cfg = load_edge_config(
            {
                "capture": {
                    "capture_min_trigger_interval_sec": 2.5,
                    "capture_rate_window_sec": 0.0,
                    "capture_rate_max_images": 0,
                }
            },
            base_dir=EDGE_SERVER_ROOT,
        )

        self.assertEqual(cfg.capture.capture_min_trigger_interval_sec, 2.5)
        self.assertEqual(cfg.capture.capture_rate_window_sec, 0.0)
        self.assertEqual(cfg.capture.capture_rate_max_images, 0)

    def test_min_interval_is_checked_before_window_limit(self) -> None:
        clock = _VirtualClock(start=100.0)
        module = SensorCameraCaptureModule(
            device_id="edge-test",
            device_name="test-device",
            location_name="test-location",
            sensor=_AlwaysMotionSensor(),
            camera=_DummyCamera(),
            environment_sensor=_DummyEnvironmentSensor(),
            capture_min_trigger_interval_sec=2.0,
            capture_rate_window_sec=10.0,
            capture_rate_max_images=3,
        )

        with (
            patch("src.ignitor.capture_module.time.monotonic", side_effect=clock.monotonic),
            patch("src.ignitor.capture_module.time.sleep", side_effect=clock.sleep),
        ):
            module.wait_and_capture()
            module.wait_and_capture()
            module.wait_and_capture()
            clock.sleep_calls.clear()
            module.wait_and_capture()

        self.assertEqual(len(clock.sleep_calls), 2)
        self.assertAlmostEqual(clock.sleep_calls[0], 2.0, places=6)
        self.assertAlmostEqual(clock.sleep_calls[1], 4.0, places=6)


if __name__ == "__main__":
    main()
