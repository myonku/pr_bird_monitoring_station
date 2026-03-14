from typing import Literal

from msgspec import Struct


CommKeyOwnerType = Literal["instance", "service"]
CommKeyStatus = Literal["active", "expired", "revoked"]
KeyExchangeAlgorithm = Literal["ecdhe_p256", "ecdhe_x25519"]
SignatureAlgorithm = Literal["ecdsa_p256_sha256", "ed25519"]
CipherSuite = Literal["chacha20_poly1305", "aes_256_gcm"]
HandshakeStatus = Literal["pending", "established", "failed", "expired"]
SecureChannelStatus = Literal["active", "expired", "revoked"]
ChannelBindingType = Literal["session", "token"]


class ServiceKeyOwner(Struct, kw_only=True):
    """表示一个服务密钥的所有者，可以是一个服务实例或整个服务。
    用于密钥管理和安全通信中标识密钥的归属。"""

    owner_type: CommKeyOwnerType = "service"
    service_id: str = ""
    service_name: str = ""
    instance_id: str = ""
    instance_name: str = ""


class ServicePublicKeyRecord(Struct, kw_only=True):
    """表示一个服务公钥的记录，包括密钥ID、所有者信息、加密算法、密钥内容、状态和时间戳等。
    用于全局公钥目录查询和验证通信对方的身份。"""

    key_id: str
    owner: ServiceKeyOwner

    key_exchange_algorithm: KeyExchangeAlgorithm
    signature_algorithm: SignatureAlgorithm
    public_key_pem: str
    fingerprint: str

    status: CommKeyStatus

    created_at: float = 0.0
    activated_at: float = 0.0
    expires_at: float = 0.0
    revoked_at: float = 0.0


class LocalPrivateKeyRef(Struct, kw_only=True):
    """表示一个本地私钥的引用，包括密钥ID、所有者信息、加密算法、私钥存储位置和加载时间等。"""

    key_id: str
    owner: ServiceKeyOwner

    key_exchange_algorithm: KeyExchangeAlgorithm
    signature_algorithm: SignatureAlgorithm

    private_key_ref: str
    loaded_at: float = 0.0


class ECDHEHandshakeRecord(Struct, kw_only=True):
    """表示一个ECDHE密钥交换握手的记录，包括握手ID、参与方信息、使用的算法、交换的公钥、生成的签名、握手状态和时间戳等。
    用于安全通信的握手过程记录和审计。"""

    id: str

    initiator: ServiceKeyOwner
    responder: ServiceKeyOwner

    initiator_key_id: str
    responder_key_id: str

    key_exchange_algorithm: KeyExchangeAlgorithm
    signature_algorithm: SignatureAlgorithm
    cipher_suite: CipherSuite

    initiator_ephemeral_public_key: str
    responder_ephemeral_public_key: str

    initiator_nonce: str
    responder_nonce: str

    initiator_signature: str
    responder_signature: str

    status: HandshakeStatus
    failure_reason: str = ""

    started_at: float = 0.0
    completed_at: float = 0.0
    expires_at: float = 0.0


class SecureChannelBinding(Struct, kw_only=True):
    """表示一个安全通道绑定，包括绑定类型、会话ID、令牌ID和令牌家族ID等信息。
    用于标识和管理安全通信的会话。"""

    binding_type: ChannelBindingType = "session"
    session_id: str = ""
    token_id: str = ""
    token_family_id: str = ""


class SecureChannelSession(Struct, kw_only=True):
    """表示一个安全通道会话的记录，包括会话ID、握手ID、绑定信息、参与方信息、
    使用的算法、生成的密钥引用、通道状态和时间戳等。"""

    id: str

    handshake_id: str
    binding: SecureChannelBinding

    source: ServiceKeyOwner
    target: ServiceKeyOwner

    local_key_id: str
    peer_key_id: str

    cipher_suite: CipherSuite
    status: SecureChannelStatus

    derived_key_ref: str
    sequence: int = 0
    established_at: float = 0.0
    last_used_at: float = 0.0
    expires_at: float = 0.0
    revoked_at: float = 0.0


class EncryptedMessageMeta(Struct, kw_only=True):
    """表示一个加密消息的元信息，包括所属安全通道、使用的密钥ID、加密算法、消息序列号、随机数和时间戳等。"""
    
    channel_id: str
    handshake_id: str
    key_id: str
    cipher_suite: CipherSuite
    sequence: int
    nonce: str
    additional_data: dict[str, str] = {}
    issued_at: float = 0.0
