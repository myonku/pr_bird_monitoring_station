from dataclasses import dataclass, field

from src.models.auth.auth import SignatureAlgorithm

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
class BootstrapAuthenticateRequest:
    """边缘端提交 bootstrap authenticate 时发送给网关的完整请求载荷。"""

    challenge: BootstrapChallenge
    signed: SignedBootstrapProof
    scopes: list[str] = field(default_factory=list)
    role: str = "device"
    require_downstream_token: bool = False
