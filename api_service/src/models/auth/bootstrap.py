from typing import Literal

from msgspec import Struct

from src.models.auth.auth import IdentityContext, Session, TokenBundle
from src.models.commsec.commsec import ServicePublicKeyRecord


BootstrapStage = Literal["uninitialized", "challenging", "authenticating", "ready"]


class ChallengeRequest(Struct, kw_only=True):
    """引导认证流程中的挑战请求，包括请求的实体类型和ID、使用的密钥ID、预期的受众、客户端信息、
    请求上下文和挑战的有效期等。"""

    entity_type: str
    entity_id: str
    key_id: str

    audience: str

    client_id: str = ""
    gateway_id: str = ""
    source_ip: str = ""
    user_agent: str = ""

    request_id: str = ""
    trace_id: str = ""

    ttl_sec: int = 60


class ChallengePayload(Struct, kw_only=True):
    """引导认证流程中的挑战负载，包括挑战ID、颁发者和受众信息、关联的实体和密钥信息、随机数和时间戳等。"""

    challenge_id: str

    issuer: str
    audience: str

    entity_type: str
    entity_id: str
    key_id: str

    nonce: str

    issued_at: float
    expires_at: float


class SignedChallengeResponse(Struct, kw_only=True):
    """表示一个签名的挑战响应，包括挑战ID、密钥ID、签名算法和签名内容等信息。"""

    challenge_id: str
    key_id: str

    signature_algorithm: str
    signature: str

    signed_at: float


class BootstrapAuthRequest(Struct, kw_only=True):
    """表示一个引导认证请求，包括挑战负载、签名的挑战响应、请求的作用域和角色等信息。"""

    challenge: ChallengePayload
    signed: SignedChallengeResponse

    scopes: list[str] = []
    role: str = ""
    require_downstream_token: bool = False


class PublicKeyLookupRequest(Struct, kw_only=True):
    """公钥查询请求，包括查询的密钥ID、相关的服务信息和查询上下文等。用于在引导认证过程中查询服务的公钥以验证签名。"""

    service_id: str = ""
    service_name: str = ""
    key_id: str = ""


class PublicKeyLookupResult(Struct, kw_only=True):
    """公钥查询结果，包括是否找到对应的公钥、查询到的公钥记录、查询失败的原因和查询的时间戳等信息。"""

    found: bool
    key: ServicePublicKeyRecord | None = None
    failure_reason: str = ""
    checked_at: float = 0.0


class BootstrapAuthResult(Struct, kw_only=True):
    """引导认证结果，包括认证阶段、身份信息、会话信息和令牌信息等。"""

    stage: BootstrapStage

    identity: IdentityContext | None = None
    session: Session | None = None
    tokens: TokenBundle | None = None

    require_app_encryption: bool = False
    active_comm_key_id: str = ""

    issued_at: float = 0.0
    expires_at: float = 0.0
