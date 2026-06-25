from abc import ABC, abstractmethod
from uuid import UUID

from msgspec import Struct

from src.models.auth.auth import TokenBundle
from src.models.auth.bootstrap import (
    BootstrapAuthRequest,
    BootstrapAuthResult,
    ChallengePayload,
    ChallengeRequest,
)


class TokenRevokeRequest(Struct, kw_only=True):
    """表示一个令牌撤销请求，包括令牌ID、家族ID和会话ID，以及撤销原因和撤销者等信息。"""

    token_id: UUID
    family_id: UUID
    session_id: UUID

    reason: str
    revoked_by: str

    request_id: str
    trace_id: str


class TokenRefreshRequest(Struct, kw_only=True):
    """表示一个令牌刷新请求，包括当前的访问令牌和刷新令牌，以及客户端信息和请求上下文等。"""

    refresh_token: str

    client_id: str
    gateway_id: str
    source_ip: str
    user_agent: str

    request_id: str
    trace_id: str


class IAuthAuthorityClient(ABC):
    """data_server 侧对认证中心的客户端调用。"""

    @abstractmethod
    async def init_bootstrap_challenge(self, req: ChallengeRequest) -> ChallengePayload:
        raise NotImplementedError

    @abstractmethod
    async def authenticate_bootstrap(
        self, req: BootstrapAuthRequest
    ) -> BootstrapAuthResult:
        raise NotImplementedError

    @abstractmethod
    async def refresh_token_bundle(self, req: TokenRefreshRequest) -> TokenBundle:
        raise NotImplementedError

    @abstractmethod
    async def revoke_token(self, req: TokenRevokeRequest) -> None:
        raise NotImplementedError
