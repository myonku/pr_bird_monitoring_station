from abc import ABC, abstractmethod
from dataclasses import dataclass
from uuid import UUID

from msgspec import Struct

from src.iface.communication.commsec_contract import ChannelEncryptResult, SecureChannelEnsureRequest
from src.models.commsec.commsec import (
    CipherSuite,
    ECDHEHandshakeRecord,
    KeyExchangeAlgorithm,
    SecureChannelBinding,
    SecureChannelSession,
    ServiceKeyOwner,
    SignatureAlgorithm,
)


class ECDHEHandshakeInitRequest(Struct, kw_only=True):
    """ECDHE 初始化请求契约。"""

    initiator: ServiceKeyOwner
    responder: ServiceKeyOwner

    initiator_key_id: str

    supported_key_exchanges: list[KeyExchangeAlgorithm]
    supported_signatures: list[SignatureAlgorithm]
    supported_cipher_suites: list[CipherSuite]

    binding: SecureChannelBinding
    ttl_sec: int


class ECDHEHandshakeInitResult(Struct, kw_only=True):
    """ECDHE 初始化结果契约。"""

    handshake: ECDHEHandshakeRecord

    selected_key_exchange: KeyExchangeAlgorithm
    selected_signature: SignatureAlgorithm
    selected_cipher_suite: CipherSuite


class ECDHEHandshakeCompleteRequest(Struct, kw_only=True):
    """ECDHE 完成请求契约。"""

    handshake_id: UUID

    responder_ephemeral_public_key: str
    responder_signature: str
    responder_nonce: str


class ECDHEHandshakeCompleteResult(Struct, kw_only=True):
    """ECDHE 完成结果契约。"""

    handshake: ECDHEHandshakeRecord
    channel: SecureChannelSession | None = None


class SecureChannelUpsertRequest(Struct, kw_only=True):
    """安全通道写入请求契约。"""

    handshake_id: UUID
    binding: SecureChannelBinding

    source: ServiceKeyOwner
    target: ServiceKeyOwner

    local_key_id: str
    peer_key_id: str

    cipher_suite: CipherSuite
    derived_key_ref: str
    ttl_sec: int


class SecureChannelQuery(Struct, kw_only=True):
    """安全通道查询请求契约。"""

    channel_id: UUID
    binding: SecureChannelBinding

    source_entity_id: str
    target_entity_id: str


class SecureChannelRevokeRequest(Struct, kw_only=True):
    """安全通道撤销请求契约。"""

    channel_id: UUID

    binding: SecureChannelBinding
    reason: str
    revoked_by: str


class ChannelEncryptRequest(Struct, kw_only=True):
    """通过安全通道进行载荷加密的请求契约。"""

    channel_id: UUID
    plaintext: str
    additional_data: dict[str, str] | None = None


class ChannelDecryptRequest(Struct, kw_only=True):
    """通过安全通道进行载荷解密的请求契约。"""

    channel_id: UUID
    ciphertext: str
    sequence: int
    additional_data: dict[str, str] | None = None


@dataclass(slots=True, kw_only=True)
class ChannelDecryptResult:
    plaintext: str
    updated_sequence: int


class ICommsecChannelManager(ABC):
    """安全通道生命周期与载荷操作。

    下游接口调用：
      - common.IKeyManager.get_private_key_ref / lookup_public_key
      - commsec 服务实现使用的密码学原语
    """

    @abstractmethod
    async def ensure_channel(self, req: SecureChannelEnsureRequest) -> SecureChannelSession:
        raise NotImplementedError

    @abstractmethod
    async def init_handshake(self, req: ECDHEHandshakeInitRequest) -> ECDHEHandshakeInitResult:
        raise NotImplementedError

    @abstractmethod
    async def complete_handshake(
        self,
        req: ECDHEHandshakeCompleteRequest,
    ) -> ECDHEHandshakeCompleteResult:
        raise NotImplementedError

    @abstractmethod
    async def upsert_channel(self, req: SecureChannelUpsertRequest) -> SecureChannelSession:
        raise NotImplementedError

    @abstractmethod
    async def get_channel(self, query: SecureChannelQuery) -> SecureChannelSession | None:
        raise NotImplementedError

    @abstractmethod
    async def revoke_channel(self, req: SecureChannelRevokeRequest) -> None:
        raise NotImplementedError

    @abstractmethod
    async def encrypt_payload(self, req: ChannelEncryptRequest) -> ChannelEncryptResult:
        raise NotImplementedError

    @abstractmethod
    async def decrypt_payload(self, req: ChannelDecryptRequest) -> ChannelDecryptResult:
        raise NotImplementedError
