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
class LocalTrustMaterial:
    """本地信任材料，包含设备的公私钥信息和相关元数据。"""

    device_id: str
    key_id: str
    signature_algorithm: SignatureAlgorithm
    private_key_ref: str
    public_key_pem: str
    fingerprint: str = ""
