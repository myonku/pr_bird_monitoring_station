from typing import Literal
from uuid import UUID

from msgspec import Struct

from src.models.auth.auth import IdentityContext, Session, TokenBundle
from src.models.common.entry import EntityType
from src.models.commsec.commsec import SignatureAlgorithm


BootstrapStage = Literal["uninitialized", "challenging", "authenticating", "ready"]


class ChallengeRequest(Struct, kw_only=True):
    """引导认证流程中的挑战请求，包括请求的实体类型和ID、使用的密钥ID、预期的受众、客户端信息、
    请求上下文和挑战的有效期等。"""

    entity_type: EntityType
    entity_id: str
    key_id: str = ""

    audience: str

    client_id: str
    gateway_id: str
    source_ip: str
    user_agent: str

    request_id: str
    trace_id: str

    ttl_sec: int


class ChallengePayload(Struct, kw_only=True):
    """引导认证流程中的挑战负载，包括挑战ID、颁发者和受众信息、关联的实体和密钥信息、随机数和时间戳等。"""

    challenge_id: UUID

    issuer: str
    audience: str

    entity_type: EntityType
    entity_id: str
    key_id: str

    nonce: str

    issued_at: float
    expires_at: float


class SignedChallengeResponse(Struct, kw_only=True):
    """表示一个签名的挑战响应，包括挑战ID、密钥ID、签名算法和签名内容等信息。"""

    challenge_id: UUID
    key_id: str

    signature_algorithm: SignatureAlgorithm
    signature: str

    signed_at: float


class BootstrapAuthRequest(Struct, kw_only=True):
    """表示一个引导认证请求，包括挑战负载、签名的挑战响应、请求的作用域和角色等信息。"""

    challenge: ChallengePayload
    signed: SignedChallengeResponse

    scopes: list[str] = []
    role: str
    require_downstream_token: bool


class BootstrapAuthResult(Struct, kw_only=True):
    """引导认证结果，包括认证阶段、身份信息、会话信息和令牌信息等。"""

    stage: BootstrapStage

    identity: IdentityContext | None
    session: Session | None
    tokens: TokenBundle | None

    active_comm_key_id: str

    issued_at: float
    expires_at: float
