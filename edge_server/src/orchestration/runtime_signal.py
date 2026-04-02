from src.models.workflow.runtime import DeviceLoadSnapshot


class ResourceMonitor:
    """采样设备资源占用并输出高负载标记。"""

    def __init__(
        self,
        cpu_high_watermark: float = 0.85,
        memory_high_watermark: float = 0.90,
        force_high_load: bool = False,
    ) -> None:
        self.cpu_high_watermark = cpu_high_watermark
        self.memory_high_watermark = memory_high_watermark
        self.force_high_load = force_high_load

    def snapshot(self) -> DeviceLoadSnapshot:
        if self.force_high_load:
            return DeviceLoadSnapshot(
                high_load=True,
                reason="force_high_load",
            )

        try:
            import psutil
        except ImportError:
            # 没有 psutil 时按非高负载处理，保证主流程可运行。
            return DeviceLoadSnapshot(
                high_load=False,
                reason="psutil_unavailable",
            )

        try:
            cpu_percent = float(psutil.cpu_percent(interval=0.0))
            memory_percent = float(psutil.virtual_memory().percent)
        except Exception as exc:
            return DeviceLoadSnapshot(
                high_load=False,
                reason=f"resource_probe_failed:{exc}",
            )

        cpu_ratio = cpu_percent / 100.0
        memory_ratio = memory_percent / 100.0
        high_load = (
            cpu_ratio >= self.cpu_high_watermark
            or memory_ratio >= self.memory_high_watermark
        )
        return DeviceLoadSnapshot(
            high_load=high_load,
            cpu_percent=cpu_percent,
            memory_percent=memory_percent,
        )
