from __future__ import annotations

import base64
import json
from time import time
from uuid import UUID, uuid4

from msgspec import json as msgjson

from src.models.commsec.commsec import ECDHEHandshakeRecord, EncryptedMessageMeta
from src.models.commsec.commsec import (
    SecureChannelSession,
)
from src.models.commsec.commsec import SecureChannelBinding, ServiceKeyOwner
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
from src.repo.redis_store import RedisManager
from src.utils.crypto_utils import CryptoUtils


NIL_UUID = UUID(int=0)


def _default_owner() -> ServiceKeyOwner:
    return ServiceKeyOwner(
        owner_type="service",
        service_id="",
        service_name="",
        instance_id="",
        instance_name="",
    )


def _default_binding() -> SecureChannelBinding:
    return SecureChannelBinding(
        binding_type="session",
        session_id=NIL_UUID,
        token_id=NIL_UUID,
        token_family_id=NIL_UUID,
    )


def _match_binding(expected: SecureChannelBinding, actual: SecureChannelBinding) -> bool:
    if expected.binding_type and expected.binding_type != actual.binding_type:
        return False
    if expected.session_id != NIL_UUID and expected.session_id != actual.session_id:
        return False
    if expected.token_id != NIL_UUID and expected.token_id != actual.token_id:
        return False
    if expected.token_family_id != NIL_UUID and expected.token_family_id != actual.token_family_id:
        return False
    return True


class CommSecurityService:
    """内部服务通信加密（ECDHE + 通道缓存）服务。"""

    def __init__(self, redis_manager: RedisManager | None = None):
        self._handshakes: dict[UUID, ECDHEHandshakeRecord] = {}
        self._channels: dict[UUID, SecureChannelSession] = {}
        self._redis_manager = redis_manager

    def _handshake_key(self, hid: UUID) -> str:
        return f"auth:commsec:handshake:id:{hid}"

    def _channel_key(self, cid: UUID) -> str:
        return f"auth:commsec:channel:id:{cid}"

    async def _cache_handshake(self, handshake: ECDHEHandshakeRecord) -> None:
        if self._redis_manager is None:
            return
        redis = self._redis_manager.get_client()
        ttl = max(int(handshake.expires_at - time()), 30)
        await redis.set(self._handshake_key(handshake.id), msgjson.encode(handshake), ex=ttl)

    async def _cache_channel(self, channel: SecureChannelSession) -> None:
        if self._redis_manager is None:
            return
        redis = self._redis_manager.get_client()
        ttl = max(int(channel.expires_at - time()), 30)
        await redis.set(self._channel_key(channel.id), msgjson.encode(channel), ex=ttl)

    async def _load_channel_from_cache(self, cid: UUID) -> SecureChannelSession | None:
        if self._redis_manager is None:
            return None
        redis = self._redis_manager.get_client()
        raw = await redis.get(self._channel_key(cid))
        if not raw:
            return None
        if isinstance(raw, str):
            raw = raw.encode("utf-8")
        return msgjson.decode(raw, type=SecureChannelSession)

    async def init_handshake(
        self, req: ECDHEHandshakeInitRequest
    ) -> ECDHEHandshakeInitResult | None:
        if req is None:
            return None
        now = time()
        ttl = req.ttl_sec if req.ttl_sec > 0 else 120
        key_exchange = (
            req.supported_key_exchanges[0]
            if req.supported_key_exchanges
            else "ecdhe_x25519"
        )
        signature_algo = (
            req.supported_signatures[0]
            if req.supported_signatures
            else "ed25519"
        )
        cipher_suite = (
            req.supported_cipher_suites[0]
            if req.supported_cipher_suites
            else "aes_256_gcm"
        )

        handshake = ECDHEHandshakeRecord(
            id=uuid4(),
            initiator=req.initiator,
            responder=req.responder,
            initiator_key_id=req.initiator_key_id,
            responder_key_id="",
            key_exchange_algorithm=key_exchange,
            signature_algorithm=signature_algo,
            cipher_suite=cipher_suite,
            initiator_ephemeral_public_key=str(CryptoUtils.derive_random_symmetric_key(16)),
            responder_ephemeral_public_key="",
            initiator_nonce=str(CryptoUtils.derive_random_symmetric_key(16)),
            responder_nonce="",
            initiator_signature="memory-signature",
            responder_signature="",
            status="pending",
            failure_reason="",
            started_at=now,
            completed_at=0.0,
            expires_at=now + ttl,
        )
        self._handshakes[handshake.id] = handshake
        await self._cache_handshake(handshake)
        return ECDHEHandshakeInitResult(
            handshake=handshake,
            selected_key_exchange=key_exchange,
            selected_signature=signature_algo,
            selected_cipher_suite=cipher_suite,
        )

    async def complete_handshake(
        self, req: ECDHEHandshakeCompleteRequest
    ) -> ECDHEHandshakeCompleteResult | None:
        handshake = self._handshakes.get(req.handshake_id)
        if handshake is None:
            return None
        if handshake.status != "pending" or time() > handshake.expires_at:
            return None

        now = time()
        derived_key = CryptoUtils.derive_session_key_by_handshake(
            handshake.key_exchange_algorithm,
            handshake.cipher_suite,
            handshake.initiator_ephemeral_public_key,
            req.responder_ephemeral_public_key,
            handshake.initiator_nonce,
            req.responder_nonce,
        )

        updated_handshake = ECDHEHandshakeRecord(
            id=handshake.id,
            initiator=handshake.initiator,
            responder=handshake.responder,
            initiator_key_id=handshake.initiator_key_id,
            responder_key_id=handshake.responder_key_id,
            key_exchange_algorithm=handshake.key_exchange_algorithm,
            signature_algorithm=handshake.signature_algorithm,
            cipher_suite=handshake.cipher_suite,
            initiator_ephemeral_public_key=handshake.initiator_ephemeral_public_key,
            responder_ephemeral_public_key=req.responder_ephemeral_public_key,
            initiator_nonce=handshake.initiator_nonce,
            responder_nonce=req.responder_nonce,
            initiator_signature=handshake.initiator_signature,
            responder_signature=req.responder_signature,
            status="established",
            failure_reason="",
            started_at=handshake.started_at,
            completed_at=now,
            expires_at=handshake.expires_at,
        )
        self._handshakes[req.handshake_id] = updated_handshake
        await self._cache_handshake(updated_handshake)

        channel = SecureChannelSession(
            id=uuid4(),
            handshake_id=req.handshake_id,
            binding=_default_binding(),
            source=updated_handshake.initiator,
            target=updated_handshake.responder,
            local_key_id=updated_handshake.initiator_key_id,
            peer_key_id=updated_handshake.responder_key_id,
            cipher_suite=updated_handshake.cipher_suite,
            status="active",
            derived_key_ref=derived_key,
            sequence=0,
            established_at=now,
            last_used_at=now,
            expires_at=updated_handshake.expires_at,
            revoked_at=0.0,
        )
        self._channels[channel.id] = channel
        await self._cache_channel(channel)
        return ECDHEHandshakeCompleteResult(handshake=updated_handshake, channel=channel)

    async def upsert_channel(
        self, req: SecureChannelUpsertRequest
    ) -> SecureChannelSession | None:
        if req is None:
            return None
        now = time()
        ttl = req.ttl_sec if req.ttl_sec > 0 else 120
        channel = SecureChannelSession(
            id=uuid4(),
            handshake_id=req.handshake_id,
            binding=req.binding,
            source=req.source,
            target=req.target,
            local_key_id=req.local_key_id,
            peer_key_id=req.peer_key_id,
            cipher_suite=req.cipher_suite,
            status="active",
            derived_key_ref=req.derived_key_ref,
            sequence=0,
            established_at=now,
            last_used_at=now,
            expires_at=now + ttl,
            revoked_at=0.0,
        )
        self._channels[channel.id] = channel
        await self._cache_channel(channel)
        return channel

    async def get_channel(
        self, req: SecureChannelQuery
    ) -> SecureChannelSession | None:
        if req is None:
            return None
        if req.channel_id != NIL_UUID:
            channel = self._channels.get(req.channel_id)
            if channel is not None:
                return channel
            cached = await self._load_channel_from_cache(req.channel_id)
            if cached is not None:
                self._channels[cached.id] = cached
                return cached
            return None

        for channel in self._channels.values():
            if req.source_service_id and channel.source.service_id != req.source_service_id:
                continue
            if req.target_service_id and channel.target.service_id != req.target_service_id:
                continue
            if not _match_binding(req.binding, channel.binding):
                continue
            return channel
        return None

    async def revoke_channel(self, req: SecureChannelRevokeRequest) -> None:
        if req is None:
            return
        now = time()
        if req.channel_id != NIL_UUID and req.channel_id in self._channels:
            channel = self._channels[req.channel_id]
            self._channels[req.channel_id] = SecureChannelSession(
                id=channel.id,
                handshake_id=channel.handshake_id,
                binding=channel.binding,
                source=channel.source,
                target=channel.target,
                local_key_id=channel.local_key_id,
                peer_key_id=channel.peer_key_id,
                cipher_suite=channel.cipher_suite,
                status="revoked",
                derived_key_ref=channel.derived_key_ref,
                sequence=channel.sequence,
                established_at=channel.established_at,
                last_used_at=channel.last_used_at,
                expires_at=channel.expires_at,
                revoked_at=now,
            )
            await self._cache_channel(self._channels[req.channel_id])
            return

        for cid, channel in list(self._channels.items()):
            if not _match_binding(req.binding, channel.binding):
                continue
            self._channels[cid] = SecureChannelSession(
                id=channel.id,
                handshake_id=channel.handshake_id,
                binding=channel.binding,
                source=channel.source,
                target=channel.target,
                local_key_id=channel.local_key_id,
                peer_key_id=channel.peer_key_id,
                cipher_suite=channel.cipher_suite,
                status="revoked",
                derived_key_ref=channel.derived_key_ref,
                sequence=channel.sequence,
                established_at=channel.established_at,
                last_used_at=channel.last_used_at,
                expires_at=channel.expires_at,
                revoked_at=now,
            )
            await self._cache_channel(self._channels[cid])

    async def encrypt_by_channel(
        self, req: ChannelEncryptRequest
    ) -> ChannelEncryptResult | None:
        channel = self._channels.get(req.channel_id)
        if channel is None or channel.status != "active" or time() > channel.expires_at:
            return None

        key = base64.b64decode(channel.derived_key_ref)
        aad = (
            json.dumps(req.additional_data, sort_keys=True).encode("utf-8")
            if req.additional_data
            else None
        )
        ciphertext = CryptoUtils.encrypt_with_cipher_suite(
            channel.cipher_suite,
            req.plaintext,
            key,
            aad,
        )

        next_seq = channel.sequence + 1
        self._channels[channel.id] = SecureChannelSession(
            id=channel.id,
            handshake_id=channel.handshake_id,
            binding=channel.binding,
            source=channel.source,
            target=channel.target,
            local_key_id=channel.local_key_id,
            peer_key_id=channel.peer_key_id,
            cipher_suite=channel.cipher_suite,
            status=channel.status,
            derived_key_ref=channel.derived_key_ref,
            sequence=next_seq,
            established_at=channel.established_at,
            last_used_at=time(),
            expires_at=channel.expires_at,
            revoked_at=channel.revoked_at,
        )
        await self._cache_channel(self._channels[channel.id])
        meta = EncryptedMessageMeta(
            channel_id=channel.id,
            handshake_id=channel.handshake_id,
            key_id=channel.local_key_id,
            cipher_suite=channel.cipher_suite,
            sequence=next_seq,
            nonce="",
            additional_data=req.additional_data or {},
            issued_at=time(),
        )
        return ChannelEncryptResult(ciphertext=ciphertext, meta=meta)

    async def decrypt_by_channel(self, req: ChannelDecryptRequest) -> str | None:
        channel = self._channels.get(req.channel_id)
        if channel is None or channel.status != "active" or time() > channel.expires_at:
            return None
        if req.sequence > 0 and req.sequence < channel.sequence:
            return None

        key = base64.b64decode(channel.derived_key_ref)
        aad = (
            json.dumps(req.additional_data, sort_keys=True).encode("utf-8")
            if req.additional_data
            else None
        )
        plaintext = CryptoUtils.decrypt_with_cipher_suite(
            channel.cipher_suite,
            req.ciphertext,
            key,
            aad,
        )

        updated_seq = max(channel.sequence, req.sequence)
        self._channels[channel.id] = SecureChannelSession(
            id=channel.id,
            handshake_id=channel.handshake_id,
            binding=channel.binding,
            source=channel.source,
            target=channel.target,
            local_key_id=channel.local_key_id,
            peer_key_id=channel.peer_key_id,
            cipher_suite=channel.cipher_suite,
            status=channel.status,
            derived_key_ref=channel.derived_key_ref,
            sequence=updated_seq,
            established_at=channel.established_at,
            last_used_at=time(),
            expires_at=channel.expires_at,
            revoked_at=channel.revoked_at,
        )
        await self._cache_channel(self._channels[channel.id])
        return plaintext
