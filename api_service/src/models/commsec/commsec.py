from __future__ import annotations

from typing import Literal
from uuid import UUID

from msgspec import Struct


CommKeyStatus = Literal["active", "expired", "revoked"]
KeyExchangeAlgorithm = Literal["ecdhe_p256", "ecdhe_x25519", "ecdhe_p384"]
SignatureAlgorithm = Literal["ecdsa_p256_sha256", "ed25519", "rsa_pss_sha256"]
CipherSuite = Literal["chacha20_poly1305", "aes_256_gcm", "aes_128_gcm"]
HandshakeStatus = Literal["pending", "established", "failed", "expired"]
SecureChannelStatus = Literal["active", "expired", "revoked"]
ChannelBindingType = Literal["session", "token"]


class ServiceKeyOwner(Struct, kw_only=True):
    """表示通信密钥所有者，统一使用 entity 维度。"""

    entity_type: str = ""
    entity_id: str = ""
    entity_name: str = ""
    instance_id: str = ""
    instance_name: str = ""

    @property
    def effective_entity_id(self) -> str:
        return self.entity_id

    @property
    def effective_entity_name(self) -> str:
        return self.entity_name or self.entity_id

    def normalized(self) -> "ServiceKeyOwner":
        entity_type = self.entity_type.strip().lower()
        entity_id = self.entity_id.strip()
        entity_name = self.entity_name.strip() or entity_id
        return ServiceKeyOwner(
            entity_type=entity_type,
            entity_id=entity_id,
            entity_name=entity_name,
            instance_id=self.instance_id.strip(),
            instance_name=self.instance_name.strip(),
        )


class ServicePublicKeyRecord(Struct, kw_only=True):
    """表示一个服务公钥目录记录。"""

    key_id: str
    owner: ServiceKeyOwner

    public_key_pem: str
    fingerprint: str

    status: CommKeyStatus

    created_at: float
    activated_at: float
    expires_at: float
    revoked_at: float


class LocalPrivateKeyRef(Struct, kw_only=True):
    """表示一个本地私钥引用。"""

    key_id: str
    owner: ServiceKeyOwner

    private_key_ref: str
    loaded_at: float


class ECDHEHandshakeRecord(Struct, kw_only=True):
    """表示一个 ECDHE 握手过程记录。"""

    id: UUID

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
    failure_reason: str

    started_at: float
    completed_at: float
    expires_at: float


class SecureChannelBinding(Struct, kw_only=True):
    """表示安全通道绑定。"""

    binding_type: ChannelBindingType
    session_id: UUID
    token_id: UUID
    token_family_id: UUID


class SecureChannelSession(Struct, kw_only=True):
    """表示一个安全通道会话。"""

    id: UUID

    handshake_id: UUID
    binding: SecureChannelBinding

    source: ServiceKeyOwner
    target: ServiceKeyOwner

    local_key_id: str
    peer_key_id: str

    cipher_suite: CipherSuite
    status: SecureChannelStatus

    derived_key_ref: str
    sequence: int
    established_at: float
    last_used_at: float
    expires_at: float
    revoked_at: float


class EncryptedMessageMeta(Struct, kw_only=True):
    """表示一个加密消息的元信息。"""

    channel_id: UUID
    handshake_id: UUID
    key_id: str
    cipher_suite: CipherSuite
    sequence: int
    nonce: str
    additional_data: dict[str, str]
    issued_at: float


class PublicKeyLookupRequest(Struct, kw_only=True):
    """统一公钥目录查询请求。"""

    key_id: str = ""
    entity_id: str = ""
    owner: ServiceKeyOwner | None = None
    require_active: bool = False

    def normalized(self) -> "PublicKeyLookupRequest":
        key_id = self.key_id.strip()
        entity_id = self.entity_id.strip()
        owner = self.owner.normalized() if self.owner is not None else None
        if owner is not None and not entity_id:
            entity_id = owner.effective_entity_id
        return PublicKeyLookupRequest(
            key_id=key_id,
            entity_id=entity_id,
            owner=owner,
            require_active=self.require_active,
        )


class PublicKeyLookupResult(Struct, kw_only=True):
    """公钥目录查询结果。"""

    found: bool
    key: ServicePublicKeyRecord | None = None
    matched_by: str = ""
    failure_reason: str = ""
    checked_at: float = 0.0
