from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from src.adapters.grpc.client_hub import GrpcClientHub
from src.usecase.security.prepare_outbound_security_uc import OutboundSecurityContext


@dataclass(slots=True)
class OutboundInvokeRequest:
    target_service: str
    rpc_method: str
    payload: bytes
    headers: dict[str, str]


@dataclass(slots=True)
class OutboundInvokeResponse:
    status_code: int
    payload: bytes
    headers: dict[str, str]


class OutboundInvokeService:
    """普通服务统一出站调用服务骨架。

    说明：
    - 入参包含目标服务与安全上下文。
    - 具体 proto 编解码与错误映射由后续业务适配器补充。
    """

    def __init__(self, client_hub: GrpcClientHub):
        self.client_hub = client_hub

    async def invoke(
        self,
        req: OutboundInvokeRequest,
        security_ctx: OutboundSecurityContext | None = None,
    ) -> OutboundInvokeResponse | None:
        _client: Any = await self.client_hub.get_client(req.target_service)
        ...
