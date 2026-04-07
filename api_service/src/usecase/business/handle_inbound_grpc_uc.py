from dataclasses import dataclass
from typing import Any


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


class HandleInboundGrpcUsecase:
    """普通服务入站业务编排。

    约束：api_service 默认不提供横向调用能力，任何出站目标标记均视为非法输入。
    """

    def __init__(self, *_: object, **__: object):
        # 保留兼容初始化签名，避免旧装配代码在迁移期直接崩溃。
        pass

    async def execute(self, req_ctx: BusinessRequestContext) -> Any:
        target_service = req_ctx.headers.get("x-outbound-target", "")
        rpc_method = req_ctx.headers.get("x-outbound-method", "")

        if target_service or rpc_method:
            return BusinessResponse(
                status_code=400,
                payload=b"cross-service outbound invoke is disabled in api_service",
                headers={
                    "x-route-key": req_ctx.route_key,
                    "x-outbound-disabled": "true",
                },
            )

        return BusinessResponse(
            status_code=200,
            payload=req_ctx.payload,
            headers={"x-route-key": req_ctx.route_key},
        )
