from __future__ import annotations

from dataclasses import dataclass

from src.models.auth.auth import DownstreamAccessGrant
from src.models.auth.auth_contract import DownstreamGrantRequest
from src.models.commsec.commsec import EncryptedMessageMeta, SecureChannelSession
from src.models.commsec.commsec_contract import (
    ChannelEncryptRequest,
    ECDHEHandshakeCompleteRequest,
    ECDHEHandshakeInitRequest,
    SecureChannelQuery,
)
from src.services.auth.downstream_grant_svc import DownstreamGrantService
from src.services.commsec.commsec_svc import CommSecurityService


@dataclass(slots=True)
class OutboundSecurityContext:
    grant: DownstreamAccessGrant | None
    channel: SecureChannelSession | None
    cipher_text: str | None = None
    encrypted_meta: EncryptedMessageMeta | None = None


@dataclass(slots=True)
class PrepareOutboundSecurityRequest:
    grant_request: DownstreamGrantRequest
    channel_query: SecureChannelQuery
    handshake_init: ECDHEHandshakeInitRequest | None = None
    encrypt_plaintext: str | None = None
    encrypt_additional_data: dict[str, str] | None = None

class PrepareOutboundSecurityUsecase:
    """出站安全上下文编排：grant + channel + optional encrypt。"""

    def __init__(
        self,
        grant_service: DownstreamGrantService,
        commsec_service: CommSecurityService,
    ):
        self.grant_service = grant_service
        self.commsec_service = commsec_service

    async def execute(
        self,
        req: PrepareOutboundSecurityRequest,
    ) -> OutboundSecurityContext:
        grant = await self.grant_service.issue_downstream_grant(req.grant_request)

        channel = await self.commsec_service.get_channel(req.channel_query)
        if channel is None and req.handshake_init is not None:
            init_res = await self.commsec_service.init_handshake(req.handshake_init)
            if init_res is not None:
                complete_res = await self.commsec_service.complete_handshake(
                    ECDHEHandshakeCompleteRequest(
                        handshake_id=init_res.handshake.id,
                        responder_ephemeral_public_key=init_res.handshake.initiator_ephemeral_public_key,
                        responder_signature=init_res.handshake.initiator_signature,
                        responder_nonce=init_res.handshake.initiator_nonce,
                    )
                )
                if complete_res and complete_res.channel:
                    channel = complete_res.channel

        if channel is None:
            return OutboundSecurityContext(grant=grant, channel=None)

        cipher_text = None
        encrypted_meta = None
        if req.encrypt_plaintext is not None:
            encrypted = await self.commsec_service.encrypt_by_channel(
                ChannelEncryptRequest(
                    channel_id=channel.id,
                    plaintext=req.encrypt_plaintext,
                    additional_data=req.encrypt_additional_data,
                )
            )
            if encrypted is not None:
                cipher_text = encrypted.ciphertext
                encrypted_meta = encrypted.meta

        return OutboundSecurityContext(
            grant=grant,
            channel=channel,
            cipher_text=cipher_text,
            encrypted_meta=encrypted_meta,
        )
