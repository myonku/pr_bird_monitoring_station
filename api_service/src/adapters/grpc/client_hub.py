from __future__ import annotations

from dataclasses import dataclass


@dataclass(slots=True)
class GrpcClientProfile:
    service_name: str
    endpoint: str
    timeout_ms: int = 3000


class GrpcClientHub:
    """普通服务模块出站 gRPC client 管理中心。

    说明：
    - 对上层暴露按服务名获取客户端的统一入口。
    - 支持按业务线注册不同 profile，以适配不同业务服务。
    """

    def __init__(self):
        self._profiles: dict[str, GrpcClientProfile] = {}
        self._clients: dict[str, object] = {}

    def register_profile(self, profile: GrpcClientProfile) -> None:
        self._profiles[profile.service_name] = profile

    async def warmup(self) -> None:
        ...

    async def get_client(self, service_name: str) -> object:
        ...

    async def close_all(self) -> None:
        ...
