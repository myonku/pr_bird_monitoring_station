from src.models.auth.auth import IssuedToken, TokenBundle, TokenVerificationResult
from src.models.auth.auth_contract import (
    TokenRefreshRequest,
    TokenRevokeRequest,
    TokenVerifyRequest,
)
from src.services.auth.auth_gateway_authority import IAuthGatewayAuthorityClient


class TokenService:
    """令牌服务（只通过认证中心处理，不维护本地令牌状态）。"""

    def __init__(self, authority_client: IAuthGatewayAuthorityClient):
        self._authority_client = authority_client

    def set_bootstrap_tokens(self, bundle: TokenBundle | None) -> None:
        # 非认证中心模块不再缓存 bootstrap 令牌。
        _ = bundle

    async def set_bootstrap_tokens_async(self, bundle: TokenBundle | None) -> None:
        _ = bundle

    async def get_access_token(self) -> IssuedToken | None:
        # 访问令牌的获取与轮换统一由认证中心处理；本地不维护状态。
        return None

    async def refresh(self, req: TokenRefreshRequest) -> TokenBundle | None:
        return await self._authority_client.refresh_by_user_session(req)

    async def verify(self, req: TokenVerifyRequest) -> TokenVerificationResult | None:
        return await self._authority_client.verify_token(req)

    async def revoke(self, req: TokenRevokeRequest) -> None:
        await self._authority_client.revoke_token(req)
