from dataclasses import dataclass


@dataclass(slots=True)
class DeviceLoadSnapshot:
    """设备负载快照，包含当前是否高负载以及相关指标（如 CPU、内存占用率等）。"""

    high_load: bool
    cpu_percent: float | None = None
    memory_percent: float | None = None
    reason: str | None = None


@dataclass(slots=True)
class RuntimeStatus:
    """边缘设备当前运行状态的综合描述，包括网络状态、负载状态以及相关指标和原因。
    用于决策引擎做出智能决策。"""

    network_ready: bool
    high_load: bool
    cpu_percent: float | None = None
    memory_percent: float | None = None
    network_reason: str | None = None
    load_reason: str | None = None


@dataclass(slots=True)
class Decision:
    """决策结果，包含是否进行本地推理、是否上传事件、是否标记需要服务器辅助，
    以及决策原因。由决策引擎输出，指导后续流程走向。"""

    do_local_infer: bool
    upload_event: bool
    mark_server_assist: bool
    reason: str = ""
