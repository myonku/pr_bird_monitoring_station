from __future__ import annotations

from typing import Literal
from msgspec import Struct


EntityType = Literal["user", "service", "device"]
SessionStatus = Literal["active", "blocked", "revoked", "expired"]
TokenType = Literal["access", "refresh", "downstream", "service"]
TokenStatus = Literal["active", "rotated", "revoked", "expired"]
TokenStorage = Literal["cache", "hybrid", "database"]
AuthMethod = Literal[
    "password",
    "device_secret",
    "service_secret",
    "refresh_token",
    "token_exchange",
]


class Principal(Struct, frozen=True):
    """表示一个主体的身份信息，包括主体类型、主体ID和一个方法来生成主体标识符。
    用于认证和授权过程中标识和验证主体的身份。"""

    entity_type: EntityType
    entity_id: str

    def principal_id(self) -> str:
        if not self.entity_type or not self.entity_id:
            return ""
        return f"{self.entity_type}:{self.entity_id}"


class IdentityContext(Struct, kw_only=True):
    """表示一个身份上下文，包括主体信息、会话信息和令牌信息等。用于在认证和授权过程中管理用户的身份和权限。"""

    principal: Principal
    entity_type: EntityType
    entity_id: str
    principal_id: str

    session_id: str
    token_id: str
    token_family_id: str
    token_type: TokenType

    role: str
    scopes: list[str]

    auth_method: AuthMethod
    source_ip: str
    client_id: str
    gateway_id: str

    source_service: str
    target_service: str

    user_agent: str
    request_id: str
    trace_id: str

    secure_channel_id: str
    secure_channel_status: str
    cipher_suite: str

    issued_at: float
    expires_at: float


class Session(Struct, kw_only=True):
    """会话模型，用于管理用户会话信息。"""

    id: str
    principal: Principal
    entity_type: EntityType
    entity_id: str
    principal_id: str

    status: SessionStatus
    auth_method: AuthMethod

    created_by_ip: str
    last_seen_ip: str
    user_agent: str
    client_id: str
    gateway_id: str

    scope_snapshot: list[str]
    role_snapshot: str
    token_family_id: str

    created_at: float
    updated_at: float
    last_seen_at: float
    last_verified_at: float
    next_refresh_at: float
    expires_at: float
    revoked_at: float
    version: int


class TokenFamily(Struct, kw_only=True):
    """用于管理一组相关的令牌，通常包括一个访问令牌和一个或多个刷新令牌。"""

    id: str
    session_id: str
    principal: Principal
    principal_id: str
    current_token: str

    status: TokenStatus
    storage: TokenStorage
    last_issued_access_id: str

    created_at: float
    last_validated_at: float
    next_refresh_at: float
    expires_at: float
    revoked_at: float
    version: int


class TokenClaims(Struct, kw_only=True):
    """令牌声明，由认证中心颁发。"""

    issuer: str
    audience: str
    subject: str
    type: TokenType

    entity_type: EntityType
    entity_id: str
    principal_id: str
    session_id: str
    token_id: str
    family_id: str
    parent_id: str

    role: str
    scopes: list[str]
    auth_method: AuthMethod

    client_id: str
    gateway_id: str
    source_service: str
    target_service: str

    issued_at: float
    expires_at: float


class TokenRecord(Struct, kw_only=True):
    """表示一个令牌的记录，包括令牌ID、所属令牌家族、会话信息、
    主体信息、令牌状态和时间戳等。用于令牌管理和验证。"""

    id: str
    family_id: str
    session_id: str

    type: TokenType
    status: TokenStatus
    storage: TokenStorage

    principal: Principal
    principal_id: str

    parent_token_id: str
    client_id: str
    gateway_id: str

    role_snapshot: str
    scope_snapshot: list[str]

    issued_at: float
    expires_at: float
    last_validated_at: float
    revoked_at: float


class IssuedToken(Struct, kw_only=True):
    """表示一个已颁发的令牌，包括令牌的原始字符串、类型、存储位置、声明信息和有效期等。
    用于在认证和授权过程中传递和验证令牌。"""

    raw: str
    type: TokenType
    storage: TokenStorage
    claims: TokenClaims
    ttl_sec: int


class TokenBundle(Struct, kw_only=True):
    """一次刷新新或颁发操作中返回的一组令牌，通常包括一个访问令牌、一个刷新令牌和一个下游令牌。"""

    access_token: IssuedToken | None
    refresh_token: IssuedToken | None
    downstream_token: IssuedToken | None


class TokenVerificationResult(Struct, kw_only=True):
    """对令牌进行验证后的结果，包括令牌是否有效、验证状态、相关的身份信息和令牌记录等。
    用于在认证和授权过程中判断令牌的有效性和权限。"""

    valid: bool
    status: TokenStatus
    identity: IdentityContext | None
    token: TokenRecord | None
    revalidation_required: bool
    failure_reason: str


class DownstreamAccessGrant(Struct, kw_only=True):
    """描述网关向内部服务转发请求时，基于原始令牌生成的下游访问授权信息，包括授权的主体信息、作用域、绑定信息和时间戳等。"""

    gateway_id: str
    source_service: str
    target_service: str

    session_id: str
    token_id: str
    principal_id: str
    binding_type: str = "session"

    scopes: list[str]

    encryption_required: bool
    secure_channel_id: str
    cipher_suite: str

    issued_at: float
    expires_at: float


class SessionTouchMeta(Struct, kw_only=True):
    """更新会话时使用的元信息，包括请求的来源IP、用户代理、客户端ID、网关ID、请求的路由和方法等。"""

    source_ip: str
    user_agent: str
    trace_id: str
    request_id: str
    client_id: str
    gateway_id: str
    route: str
    method: str
