from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from src.usecase.security.prepare_outbound_security_uc import (
    OutboundSecurityContext,
    PrepareOutboundSecurityUsecase,
)


@dataclass(slots=True)
class BusinessRequestContext:
    method: str
    headers: dict[str, str]
    payload: bytes
    route_key: str


class HandleInboundGrpcUsecase:
    """普通服务入站业务编排骨架。

    说明：
    - 负责把 gRPC handler 输入转换为业务上下文。
    - 业务需要跨服务调用时，通过 security usecase 获取出站安全上下文。
    """

    def __init__(self, security_usecase: PrepareOutboundSecurityUsecase):
        self.security_usecase = security_usecase

    async def execute(self, req_ctx: BusinessRequestContext) -> Any:
        _security_ctx: OutboundSecurityContext | None = None
        ...
