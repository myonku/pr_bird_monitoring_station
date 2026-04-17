from src.iface.workflow_interface import ITemperatureHumiditySensor
from src.models.workflow.workflow import TemperatureHumiditySnapshot


class MockTemperatureHumiditySensor(ITemperatureHumiditySensor):
    """伪环境传感器：不依赖真实硬件，直接产出可测试的温湿度数据。"""

    def __init__(
        self,
        base_temperature_c: float = 22.8,
        base_humidity_pct: float = 56.0,
    ) -> None:
        self._base_temperature_c = float(base_temperature_c)
        self._base_humidity_pct = float(base_humidity_pct)
        self._sample_index = 0

    def read_snapshot(self) -> TemperatureHumiditySnapshot:
        sample_index = self._sample_index
        self._sample_index += 1

        temperature_c = round(self._base_temperature_c + (sample_index % 5) * 0.3, 2)
        humidity_pct = int(
            max(0, min(100, round(self._base_humidity_pct + (sample_index % 7) * 2 - 6)))
        )

        return TemperatureHumiditySnapshot(
            temperature_c=temperature_c,
            humidity_pct=humidity_pct,
            source="pseudo_mock",
            sensor_snapshot={
                "sensor_mode": "mock",
                "sample_index": sample_index,
            },
        )

    def close(self) -> None:
        return None