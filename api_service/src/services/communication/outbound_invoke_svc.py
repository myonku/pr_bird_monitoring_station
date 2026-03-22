from __future__ import annotations

from dataclasses import dataclass

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
        client = await self.client_hub.get_client(req.target_service)
        headers = dict(req.headers)
        if security_ctx and security_ctx.grant:
            headers["x-downstream-principal"] = security_ctx.grant.principal_id
            headers["x-downstream-gateway"] = security_ctx.grant.gateway_id
            headers["x-downstream-target"] = security_ctx.grant.target_service
        if security_ctx and security_ctx.channel:
            headers["x-secure-channel-id"] = str(security_ctx.channel.id)
            headers["x-cipher-suite"] = security_ctx.channel.cipher_suite

        payload = req.payload
        if security_ctx and security_ctx.cipher_text:
            payload = security_ctx.cipher_text.encode("utf-8")

        resp = await client.invoke(req.rpc_method, payload, headers) # type: ignore
        return OutboundInvokeResponse(
            status_code=resp.status_code,
            payload=resp.payload,
            headers=resp.headers,
        )
