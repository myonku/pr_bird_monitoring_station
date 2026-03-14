from src.models.commsec.commsec import (
    SecureChannelSession,
)
from src.models.commsec.commsec_contract import (
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

    def __init__(self):
        ...

    async def init_handshake(
        self, ctx: object, req: ECDHEHandshakeInitRequest
    ) -> ECDHEHandshakeInitResult | None:
        ...

    async def complete_handshake(
        self, ctx: object, req: ECDHEHandshakeCompleteRequest
    ) -> ECDHEHandshakeCompleteResult | None:
        ...

    async def upsert_channel(
        self, ctx: object, req: SecureChannelUpsertRequest
    ) -> SecureChannelSession | None:
        ...

    async def get_channel(
        self, ctx: object, req: SecureChannelQuery
    ) -> SecureChannelSession | None:
        ...

    async def revoke_channel(self, ctx: object, req: SecureChannelRevokeRequest) -> None:
        ...
