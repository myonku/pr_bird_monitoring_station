from __future__ import annotations

from dataclasses import dataclass

from src.adapters.grpc.server_adapter import InMemoryGrpcResponse, resolve_inmemory_server


@dataclass(slots=True)
class GrpcClientProfile:
    service_name: str
    endpoint: str
    timeout_ms: int = 3000


class InMemoryGrpcClient:
    """内存版 gRPC 客户端，转发到本进程内 server adapter。"""

    def __init__(self, profile: GrpcClientProfile):
        self.profile = profile

    async def invoke(
        self,
        rpc_method: str,
        payload: bytes,
        headers: dict[str, str] | None = None,
    ) -> InMemoryGrpcResponse:
        server = resolve_inmemory_server(self.profile.endpoint)
        if server is None:
            return InMemoryGrpcResponse(
                status_code=503,
                payload=(
                    f"target {self.profile.service_name} not available at "
                    f"{self.profile.endpoint}"
                ).encode("utf-8"),
                headers={},
            )
        return await server.handle_unary(rpc_method, payload, headers or {})


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
        for service_name in list(self._profiles.keys()):
            await self.get_client(service_name)

    async def get_client(self, service_name: str) -> object:
        cached = self._clients.get(service_name)
        if cached is not None:
            return cached
        profile = self._profiles.get(service_name)
        if profile is None:
            raise KeyError(f"grpc profile not found: {service_name}")
        client = InMemoryGrpcClient(profile)
        self._clients[service_name] = client
        return client

    async def close_all(self) -> None:
        self._clients.clear()
