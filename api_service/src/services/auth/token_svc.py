from src.models.auth.auth import IssuedToken, TokenBundle, TokenVerificationResult
from src.models.auth.auth_contract import (
    TokenRefreshRequest,
    TokenRevokeRequest,
    TokenVerifyRequest,
)


class TokenService:
    """令牌服务。运行期不回源认证中心。"""

    def __init__(self) -> None:
        pass

    def set_bootstrap_tokens(self, bundle: TokenBundle | None) -> None:
        # 非认证中心模块不再缓存 bootstrap 令牌。
        _ = bundle

    async def set_bootstrap_tokens_async(self, bundle: TokenBundle | None) -> None:
        _ = bundle

    async def get_access_token(self) -> IssuedToken | None:
        # 访问令牌的获取与轮换统一由认证中心处理；本地不维护状态。
        return None

    async def refresh(self, req: TokenRefreshRequest) -> TokenBundle | None:
        _ = req
        return None

    async def verify(self, req: TokenVerifyRequest) -> TokenVerificationResult | None:
        _ = req
        return None

    async def revoke(self, req: TokenRevokeRequest) -> None:
        _ = req
