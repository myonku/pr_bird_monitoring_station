import sys
from pathlib import Path
from types import SimpleNamespace
from unittest import TestCase, main
from unittest.mock import patch


EDGE_SERVER_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(EDGE_SERVER_ROOT))

from src.ignitor.camera_module import PiCameraController
from src.ignitor.sensor_module import PIRMotionSensor


class _FakeCamera:
    created_camera_nums: list[int] = []
    started_camera_nums: list[int] = []

    def __init__(self, camera_num: int = 0) -> None:
        self.camera_num = camera_num
        self.configured = False
        self.started = False
        self.closed = False
        self.__class__.created_camera_nums.append(camera_num)
        if camera_num == 0:
            raise RuntimeError("camera 0 is busy")

    @staticmethod
    def global_camera_info() -> list[dict[str, object]]:
        return [
            {"Num": 0, "Id": "cam-0", "Model": "ov5647"},
            {"Num": 1, "Id": "cam-1", "Model": "imx219"},
        ]

    def create_still_configuration(self, main: dict[str, tuple[int, int]]):
        self.main_size = main["size"]
        return {"size": self.main_size}

    def configure(self, camera_cfg) -> None:
        self.configured = True
        self.camera_cfg = camera_cfg

    def start(self) -> None:
        self.started = True
        self.__class__.started_camera_nums.append(self.camera_num)

    def close(self) -> None:
        self.closed = True


class HardwareAdapterTests(TestCase):
    def setUp(self) -> None:
        _FakeCamera.created_camera_nums = []
        _FakeCamera.started_camera_nums = []

    def test_pi_camera_controller_selects_first_usable_camera(self) -> None:
        fake_picamera2_module = SimpleNamespace(Picamera2=_FakeCamera)

        with patch("src.ignitor.camera_module.importlib.import_module", return_value=fake_picamera2_module):
            controller = PiCameraController(image_width=1280, image_height=720)

        self.assertEqual(controller.camera_num, 1)
        self.assertEqual(_FakeCamera.created_camera_nums, [0, 1])
        self.assertEqual(_FakeCamera.started_camera_nums, [1])

    def test_pi_camera_controller_raises_when_no_camera_is_detected(self) -> None:
        class _NoCameraPicamera2:
            @staticmethod
            def global_camera_info() -> list[dict[str, object]]:
                return []

        fake_picamera2_module = SimpleNamespace(Picamera2=_NoCameraPicamera2)

        with patch("src.ignitor.camera_module.importlib.import_module", return_value=fake_picamera2_module):
            with self.assertRaises(RuntimeError) as context:
                PiCameraController(image_width=1280, image_height=720)

        self.assertIn("No Picamera2 camera detected", str(context.exception))

    def test_pir_motion_sensor_fails_fast_when_gpiozero_button_init_fails(self) -> None:
        class _FailingButton:
            def __init__(self, pin: int, pull_up: bool = False) -> None:
                raise RuntimeError(f"GPIO {pin} not available")

        fake_gpiozero_module = SimpleNamespace(Button=_FailingButton)

        with patch("src.ignitor.sensor_module.importlib.import_module", return_value=fake_gpiozero_module):
            with self.assertRaises(RuntimeError) as context:
                PIRMotionSensor(pir_gpio_pin=17)

        self.assertIn("failed to initialize PIR sensor on GPIO 17", str(context.exception))


if __name__ == "__main__":
    main()