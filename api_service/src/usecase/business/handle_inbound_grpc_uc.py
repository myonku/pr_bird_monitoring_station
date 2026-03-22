from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from uuid import UUID

from src.models.auth.auth import IdentityContext, Principal
from src.models.auth.auth_contract import DownstreamGrantRequest
from src.models.commsec.commsec import SecureChannelBinding
from src.models.commsec.commsec_contract import SecureChannelQuery
from src.services.communication.outbound_invoke_svc import (
    OutboundInvokeRequest,
    OutboundInvokeService,
)
from src.usecase.security.prepare_outbound_security_uc import (
    OutboundSecurityContext,
    PrepareOutboundSecurityRequest,
    PrepareOutboundSecurityUsecase,
)


@dataclass(slots=True)
class BusinessRequestContext:
    method: str
    headers: dict[str, str]
    payload: bytes
    route_key: str


@dataclass(slots=True)
class BusinessResponse:
    status_code: int
    payload: bytes
    headers: dict[str, str]


NIL_UUID = UUID(int=0)


class HandleInboundGrpcUsecase:
    """普通服务入站业务编排骨架。

    说明：
    - 负责把 gRPC handler 输入转换为业务上下文。
    - 业务需要跨服务调用时，通过 security usecase 获取出站安全上下文。
    """

    def __init__(
        self,
        security_usecase: PrepareOutboundSecurityUsecase,
        outbound_invoke_service: OutboundInvokeService | None = None,
    ):
        self.security_usecase = security_usecase
        self.outbound_invoke_service = outbound_invoke_service

    async def execute(self, req_ctx: BusinessRequestContext) -> Any:
        target_service = req_ctx.headers.get("x-outbound-target", "")
        rpc_method = req_ctx.headers.get("x-outbound-method", "")

        # 普通本地响应路径：没有跨服务目标时直接返回回显。
        if not target_service or not rpc_method or self.outbound_invoke_service is None:
            return BusinessResponse(
                status_code=200,
                payload=req_ctx.payload,
                headers={"x-route-key": req_ctx.route_key},
            )

        identity = IdentityContext(
            principal=Principal(entity_type="service", entity_id="api_service"),
            entity_type="service",
            entity_id="api_service",
            principal_id="service:api_service",
            session_id=NIL_UUID,
            token_id=NIL_UUID,
            token_family_id=NIL_UUID,
            token_type="service",
            role="service",
            scopes=["internal.invoke"],
            auth_method="service_secret",
            source_ip="",
            client_id="",
            gateway_id=req_ctx.headers.get("x-gateway-id", ""),
            source_service="api_service",
            target_service=target_service,
            user_agent="",
            request_id=req_ctx.headers.get("x-request-id", ""),
            trace_id=req_ctx.headers.get("x-trace-id", ""),
            secure_channel_id=NIL_UUID,
            secure_channel_status="",
            cipher_suite="",
            issued_at=0.0,
            expires_at=0.0,
        )

        security_ctx: OutboundSecurityContext = await self.security_usecase.execute(
            PrepareOutboundSecurityRequest(
                grant_request=DownstreamGrantRequest(
                    identity=identity,
                    target_service=target_service,
                    binding_type="session",
                    require_encryption=False,
                    ttl_sec=120,
                ),
                channel_query=SecureChannelQuery(
                    channel_id=NIL_UUID,
                    binding=SecureChannelBinding(
                        binding_type="session",
                        session_id=NIL_UUID,
                        token_id=NIL_UUID,
                        token_family_id=NIL_UUID,
                    ),
                    source_service_id="api_service",
                    target_service_id=target_service,
                ),
                handshake_init=None,
                encrypt_plaintext=None,
                encrypt_additional_data=None,
            )
        )

        outbound_resp = await self.outbound_invoke_service.invoke(
            OutboundInvokeRequest(
                target_service=target_service,
                rpc_method=rpc_method,
                payload=req_ctx.payload,
                headers=req_ctx.headers,
            ),
            security_ctx,
        )
        if outbound_resp is None:
            return BusinessResponse(status_code=502, payload=b"outbound invoke failed", headers={})

        return BusinessResponse(
            status_code=outbound_resp.status_code,
            payload=outbound_resp.payload,
            headers=outbound_resp.headers,
        )
