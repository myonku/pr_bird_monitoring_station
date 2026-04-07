from typing import Protocol

from src.models.auth.auth import (
    Session,
    TokenBundle,
    TokenVerificationResult,
)
from src.models.auth.auth_contract import (
    SessionRevokeRequest,
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


class IAuthAuthorityClient(Protocol):
    """模块直连认证中心的统一鉴权门面客户端协议。"""

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

    async def refresh_module_token(
        self, req: TokenRefreshRequest
    ) -> TokenBundle | None:
        ...

    async def revoke_module_session(self, req: SessionRevokeRequest) -> None:
        ...

    # 历史兼容：客户端用户会话续期。
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
