from src.models.auth.auth import (
    DownstreamAccessGrant,
    Session,
    SessionTouchMeta,
    TokenBundle,
    TokenVerificationResult,
)
from src.models.auth.auth_contract import (
    DownstreamGrantRequest,
    SessionValidateRequest,
    TokenRefreshRequest,
    TokenRevokeRequest,
    TokenVerifyRequest,
)
from src.models.auth.bootstrap import (
    BootstrapAuthRequest,
    BootstrapAuthResult,
    ChallengePayload,
    ChallengeRequest,
)


class AuthClient:
    """统一认证客户端：引导认证、令牌、会话、下游授权。"""

    def __init__(self):
        ...

    async def init_challenge(self, ctx: object, req: ChallengeRequest) -> ChallengePayload:
        ...

    async def authenticate_bootstrap(
        self, ctx: object, req: BootstrapAuthRequest
    ) -> BootstrapAuthResult:
        ...

    async def refresh_token_bundle(
        self, ctx: object, req: TokenRefreshRequest
    ) -> TokenBundle | None:
        ...

    async def verify_token(
        self, ctx: object, req: TokenVerifyRequest
    ) -> TokenVerificationResult | None:
        ...

    async def revoke_token(self, ctx: object, req: TokenRevokeRequest) -> None:
        ...

    async def get_session(self, ctx: object, session_id: str) -> Session | None:
        ...

    async def touch_session(
        self, ctx: object, session_id: str, meta: SessionTouchMeta
    ) -> None:
        ...

    async def validate_session(
        self, ctx: object, req: SessionValidateRequest
    ) -> Session | None:
        ...

    async def issue_downstream_grant(
        self, ctx: object, req: DownstreamGrantRequest
    ) -> DownstreamAccessGrant | None:
        ...
