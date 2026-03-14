from msgspec import Struct

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
    """表示ECDHE握手初始化请求参数。"""

    initiator: ServiceKeyOwner
    responder: ServiceKeyOwner

    initiator_key_id: str

    supported_key_exchanges: list[KeyExchangeAlgorithm]
    supported_signatures: list[SignatureAlgorithm]
    supported_cipher_suites: list[CipherSuite]

    binding: SecureChannelBinding
    ttl_sec: int


class ECDHEHandshakeInitResult(Struct, kw_only=True):
    """表示ECDHE握手初始化结果，包括握手记录和选定的算法等信息。"""

    handshake: ECDHEHandshakeRecord

    selected_key_exchange: KeyExchangeAlgorithm
    selected_signature: SignatureAlgorithm
    selected_cipher_suite: CipherSuite


class ECDHEHandshakeCompleteRequest(Struct, kw_only=True):
    """表示ECDHE握手完成请求参数。"""

    handshake_id: str

    responder_ephemeral_public_key: str
    responder_signature: str
    responder_nonce: str


class ECDHEHandshakeCompleteResult(Struct, kw_only=True):
    """表示ECDHE握手完成结果，包括握手记录和安全通道会话。"""

    handshake: ECDHEHandshakeRecord
    channel: SecureChannelSession | None = None


class SecureChannelUpsertRequest(Struct, kw_only=True):
    """表示建立或更新通道缓存请求。"""

    handshake_id: str
    binding: SecureChannelBinding

    source: ServiceKeyOwner
    target: ServiceKeyOwner

    local_key_id: str
    peer_key_id: str

    cipher_suite: CipherSuite
    derived_key_ref: str
    ttl_sec: int


class SecureChannelQuery(Struct, kw_only=True):
    """表示查询安全通道请求。"""

    channel_id: str
    binding: SecureChannelBinding

    source_service_id: str
    target_service_id: str


class SecureChannelRevokeRequest(Struct, kw_only=True):
    """表示撤销安全通道请求。"""

    channel_id: str

    binding: SecureChannelBinding
    reason: str
    revoked_by: str
