from src.models.commsec.commsec import (
    SecureChannelSession,
)
from src.models.commsec.commsec_contract import (
    ChannelDecryptRequest,
    ChannelEncryptRequest,
    ChannelEncryptResult,
    ECDHEHandshakeCompleteRequest,
    ECDHEHandshakeCompleteResult,
    ECDHEHandshakeInitRequest,
    ECDHEHandshakeInitResult,
    SecureChannelQuery,
    SecureChannelRevokeRequest,
    SecureChannelUpsertRequest,
)


class CommSecurityService:
    """内部服务通信加密（ECDHE + 通道缓存）服务。"""

    def __init__(self): ...

    async def init_handshake(
        self, req: ECDHEHandshakeInitRequest
    ) -> ECDHEHandshakeInitResult | None: ...

    async def complete_handshake(
        self, req: ECDHEHandshakeCompleteRequest
    ) -> ECDHEHandshakeCompleteResult | None: ...

    async def upsert_channel(
        self, req: SecureChannelUpsertRequest
    ) -> SecureChannelSession | None: ...

    async def get_channel(
        self, req: SecureChannelQuery
    ) -> SecureChannelSession | None: ...

    async def revoke_channel(self, req: SecureChannelRevokeRequest) -> None: ...

    async def encrypt_by_channel(
        self, req: ChannelEncryptRequest
    ) -> ChannelEncryptResult | None: ...

    async def decrypt_by_channel(self, req: ChannelDecryptRequest) -> str | None: ...
