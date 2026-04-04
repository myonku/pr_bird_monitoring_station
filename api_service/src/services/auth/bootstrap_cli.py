from typing import cast

from src.models.auth.bootstrap import (
    BootstrapAuthRequest,
    BootstrapAuthResult,
    BootstrapStage,
    ChallengePayload,
    ChallengeRequest,
)
from src.services.auth.auth_gateway_authority import IAuthGatewayAuthorityClient


class BootstrapClient:
    """冷启动认证流程服务（只转发认证中心）。"""

    def __init__(self, authority_client: IAuthGatewayAuthorityClient):
        self._authority_client = authority_client

    async def init_challenge(self, req: ChallengeRequest) -> ChallengePayload:
        return await self._authority_client.init_challenge(req)

    async def authenticate_bootstrap(
        self, req: BootstrapAuthRequest
    ) -> BootstrapAuthResult:
        return await self._authority_client.authenticate_bootstrap(req)

    async def get_bootstrap_stage(self, ctx: object) -> BootstrapStage:
        principal_id = ""
        if isinstance(ctx, dict):
            principal_id = str(ctx.get("principal_id") or "")
        elif isinstance(ctx, str):
            principal_id = ctx
        principal_id = principal_id.strip()
        if not principal_id or ":" not in principal_id:
            return "uninitialized"
        entity_type, entity_id = principal_id.split(":", 1)
        entity_type = entity_type.strip()
        entity_id = entity_id.strip()
        if not entity_type or not entity_id:
            return "uninitialized"
        stage = await self._authority_client.get_bootstrap_stage(entity_type, entity_id)
        return cast(BootstrapStage, stage)
