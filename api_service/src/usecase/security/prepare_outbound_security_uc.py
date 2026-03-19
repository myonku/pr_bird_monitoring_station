from __future__ import annotations

from dataclasses import dataclass

from src.models.auth.auth import DownstreamAccessGrant
from src.models.commsec.commsec import EncryptedMessageMeta, SecureChannelSession
from src.models.commsec.commsec_contract import ChannelEncryptRequest
from src.services.auth.downstream_grant_svc import DownstreamGrantService
from src.services.commsec.commsec_svc import CommSecurityService


@dataclass(slots=True)
class OutboundSecurityContext:
    grant: DownstreamAccessGrant | None
    channel: SecureChannelSession | None
    cipher_text: str | None = None
    encrypted_meta: EncryptedMessageMeta | None = None


class PrepareOutboundSecurityUsecase:
    """出站安全上下文编排：grant + channel + optional encrypt。"""

    def __init__(
        self,
        grant_service: DownstreamGrantService,
        commsec_service: CommSecurityService,
    ):
        self.grant_service = grant_service
        self.commsec_service = commsec_service

    async def execute(self, encrypt_req: ChannelEncryptRequest | None = None) -> OutboundSecurityContext:
        ...
