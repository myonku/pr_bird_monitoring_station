from msgspec import Struct

from src.models.auth.auth import (
    AuthMethod,
    IdentityContext,
    Principal,
    TokenType,
)
from src.models.commsec.commsec import ChannelBindingType


class TokenIssueRequest(Struct, kw_only=True):
    """表示签发任意类型令牌的请求。"""

    principal: Principal

    token_type: TokenType
    session_id: str
    family_id: str

    audience: str
    role: str
    scopes: list[str]

    auth_method: AuthMethod

    client_id: str
    gateway_id: str
    source_service: str
    target_service: str

    parent_token_id: str
    ttl_sec: int


class TokenRefreshRequest(Struct, kw_only=True):
    """表示刷新令牌的请求。"""

    refresh_token: str

    client_id: str
    gateway_id: str
    source_ip: str
    user_agent: str

    request_id: str
    trace_id: str


class TokenVerifyRequest(Struct, kw_only=True):
    """表示令牌校验参数。"""

    raw_token: str

    expected_types: list[TokenType]
    expected_audience: str
    require_scopes: list[str]

    source_service: str
    target_service: str

    allow_expired_skew_sec: int


class TokenRevokeRequest(Struct, kw_only=True):
    """表示令牌撤销参数。"""

    token_id: str
    family_id: str
    session_id: str

    reason: str
    revoked_by: str

    request_id: str
    trace_id: str


class SessionIssueRequest(Struct, kw_only=True):
    """表示创建会话参数。"""

    principal: Principal
    role: str
    scopes: list[str]

    auth_method: AuthMethod

    client_id: str
    gateway_id: str
    source_ip: str
    user_agent: str

    expires_at: float


class SessionValidateRequest(Struct, kw_only=True):
    """表示会话校验参数。"""

    session_id: str
    principal_id: str
    require_active: bool
    min_version: int


class SessionRevokeRequest(Struct, kw_only=True):
    """表示会话撤销参数。"""

    session_id: str
    principal_id: str

    reason: str
    revoked_by: str

    request_id: str
    trace_id: str


class DownstreamGrantRequest(Struct, kw_only=True):
    """表示网关申请下游服务授权参数。"""

    identity: IdentityContext

    target_service: str
    binding_type: ChannelBindingType

    require_encryption: bool
    ttl_sec: int
