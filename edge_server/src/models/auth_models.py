from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal


TokenType = Literal["access", "refresh"]
SignatureAlgorithm = Literal[
    "ecdsa_p256_sha256",
    "ed25519",
    "rsa_pss_sha256",
]
AuthStage = Literal[
    "uninitialized",
    "challenge_issued",
    "ready",
    "refreshing",
    "expired",
    "revoked",
    "failed",
]
SessionStatus = Literal["active", "expired", "revoked"]


@dataclass(slots=True)
class LocalTrustMaterial:
    """本地信任材料，包含设备的公私钥信息和相关元数据。"""

    device_id: str
    key_id: str
    signature_algorithm: SignatureAlgorithm
    private_key_ref: str
    public_key_pem: str
    fingerprint: str = ""


@dataclass(slots=True)
class BootstrapChallenge:
    """引导挑战，由认证中心生成并发送给边缘设备，用于启动认证流程。"""

    challenge_id: str
    nonce: str
    issuer: str
    audience: str
    issued_at: float
    expires_at: float
    entity_type: str = "device"
    entity_id: str = ""
    key_id: str = ""


@dataclass(slots=True)
class SignedBootstrapProof:
    """引导证明，由边缘设备使用本地私钥对挑战进行签名生成，发送给认证中心进行验证。"""

    challenge_id: str
    device_id: str
    key_id: str
    signature: str
    signature_algorithm: SignatureAlgorithm
    signed_at: float


@dataclass(slots=True)
class EdgeToken:
    """边缘令牌，包含访问令牌和刷新令牌的相关信息，用于边缘设备与网关之间的认证和授权。"""

    raw: str
    token_type: TokenType
    token_id: str
    family_id: str
    session_id: str
    issued_at: float
    expires_at: float
    scopes: list[str] = field(default_factory=list)
    role: str = ""


@dataclass(slots=True)
class EdgeTokenBundle:
    """边缘令牌包，包含一对访问令牌和刷新令牌，以及相关的元数据。"""

    access_token: EdgeToken | None
    refresh_token: EdgeToken | None


@dataclass(slots=True)
class EdgeSession:
    """边缘会话，表示边缘设备与网关之间的认证会话状态和相关信息。"""

    session_id: str
    principal_id: str
    device_id: str
    status: SessionStatus
    issued_at: float
    expires_at: float
    token_family_id: str
    last_verified_at: float = 0.0


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
