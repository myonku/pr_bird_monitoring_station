from src.models.auth.auth import IssuedToken, TokenBundle, TokenVerificationResult
from src.models.auth.auth_contract import (
    TokenRefreshRequest,
    TokenRevokeRequest,
    TokenVerifyRequest,
)


class TokenService:
    """令牌签发、刷新和校验服务。"""

    def __init__(self):
        ...

    async def get_access_token(self, ctx: object) -> IssuedToken | None:
        ...

    async def refresh(
        self, ctx: object, req: TokenRefreshRequest
    ) -> TokenBundle | None:
        ...

    async def verify(
        self, ctx: object, req: TokenVerifyRequest
    ) -> TokenVerificationResult | None:
        ...

    async def revoke(self, ctx: object, req: TokenRevokeRequest) -> None:
        ...
