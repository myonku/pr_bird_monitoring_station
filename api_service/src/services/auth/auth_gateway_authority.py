from typing import Protocol

from src.models.auth.auth import (
    DownstreamAccessGrant,
    Session,
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
    BootstrapStage,
    BootstrapAuthRequest,
    BootstrapAuthResult,
    ChallengePayload,
    ChallengeRequest,
)


class IAuthGatewayAuthorityClient(Protocol):
    """认证中心统一鉴权门面客户端协议。"""

    async def init_challenge(self, req: ChallengeRequest) -> ChallengePayload:
        ...

    async def authenticate_bootstrap(
        self, req: BootstrapAuthRequest
    ) -> BootstrapAuthResult:
        ...

    async def get_bootstrap_stage(
        self, entity_type: str, entity_id: str
    ) -> BootstrapStage:
        ...

    async def issue_downstream_grant(
        self, req: DownstreamGrantRequest
    ) -> DownstreamAccessGrant:
        ...

    async def refresh_by_user_session(
        self, req: TokenRefreshRequest
    ) -> TokenBundle | None:
        ...

    async def verify_token(
        self, req: TokenVerifyRequest
    ) -> TokenVerificationResult | None:
        ...

    async def revoke_token(self, req: TokenRevokeRequest) -> None:
        ...

    async def validate_session(
        self, req: SessionValidateRequest
    ) -> Session | None:
        ...
