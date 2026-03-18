from src.models.auth.auth import IssuedToken, TokenBundle, TokenVerificationResult
from src.models.auth.auth_contract import (
    TokenRefreshRequest,
    TokenRevokeRequest,
    TokenVerifyRequest,
)


class TokenService:
    """令牌签发、刷新和校验服务。"""

    def __init__(self): ...

    async def get_access_token(self) -> IssuedToken | None: ...

    async def refresh(self, req: TokenRefreshRequest) -> TokenBundle | None: ...

    async def verify(
        self, req: TokenVerifyRequest
    ) -> TokenVerificationResult | None: ...

    async def revoke(self, req: TokenRevokeRequest) -> None: ...
