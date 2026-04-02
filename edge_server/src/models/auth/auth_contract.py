from dataclasses import dataclass, field

from src.models.auth.auth import AuthStage, EdgeSession, EdgeTokenBundle, TokenType


@dataclass(slots=True)
class TokenVerificationResult:
    """令牌验证结果，表示对边缘令牌进行验证后的结果和相关信息。"""

    valid: bool
    status: str
    failure_reason: str = ""


@dataclass(slots=True)
class RefreshTokenRequest:
    refresh_token: str
    client_id: str
    gateway_id: str
    source_ip: str
    user_agent: str
    request_id: str
    trace_id: str


@dataclass(slots=True)
class EdgeAuthHeaders:
    """发送给网关的认证HTTP头，包含必要的认证信息和上下文，用于网关进行身份验证和授权决策。"""

    authorization: str
    session_id: str
    token_id: str
    token_type: TokenType
    principal_id: str
    scopes: list[str] = field(default_factory=list)

    def to_http_headers(self) -> dict[str, str]:
        out = {
            "Authorization": self.authorization,
            "x-downstream-session": self.session_id,
            "x-downstream-token": self.token_id,
            "x-token-type": self.token_type,
            "x-downstream-principal": self.principal_id,
        }
        if self.scopes:
            out["x-scopes"] = ",".join(self.scopes)
        return out


@dataclass(slots=True)
class EdgeAuthState:
    stage: AuthStage
    session: EdgeSession | None
    tokens: EdgeTokenBundle | None
    failure_reason: str = ""
