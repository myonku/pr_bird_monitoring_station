# pyright: reportAttributeAccessIssue=false
from __future__ import annotations

import asyncio
import base64
import time
from dataclasses import dataclass

import grpc
from src.gen.auth.v1 import auth_authority_bootstrap_pb2 as bootstrap_pb2
from src.gen.auth.v1 import auth_authority_bootstrap_pb2_grpc as bootstrap_pb2_grpc


BOOTSTRAP_INIT_METHOD = "/bms.auth.v1.AuthAuthorityBootstrapService/InitBootstrapChallenge"
BOOTSTRAP_AUTH_METHOD = "/bms.auth.v1.AuthAuthorityBootstrapService/AuthenticateBootstrap"


@dataclass(slots=True, kw_only=True)
class BootstrapHandshakeResult:
    stage: str
    active_comm_key_id: str = ""


class AuthAuthorityBootstrapRPCClient:
    def __init__(
        self,
        endpoint: str,
        *,
        dial_timeout_sec: float = 3.0,
        call_timeout_sec: float = 5.0,
    ) -> None:
        self._endpoint = (endpoint or "").strip()
        self._dial_timeout_sec = dial_timeout_sec
        self._call_timeout_sec = call_timeout_sec

    async def execute_bootstrap_handshake(
        self,
        *,
        entity_type: str,
        entity_id: str,
        audience: str,
        key_id: str,
    ) -> BootstrapHandshakeResult:
        if not self._endpoint:
            raise ValueError("auth authority endpoint is required")

        payload = {
            "entity_type": (entity_type or "").strip(),
            "entity_id": (entity_id or "").strip(),
            "audience": (audience or "").strip(),
            "key_id": (key_id or "").strip(),
            "ttl_sec": 60,
        }
        if not payload["entity_type"] or not payload["entity_id"]:
            raise ValueError("bootstrap entity_type and entity_id are required")

        async with grpc.aio.insecure_channel(self._endpoint) as channel:
            await asyncio.wait_for(
                channel.channel_ready(),
                timeout=self._dial_timeout_sec,
            )
            stub = bootstrap_pb2_grpc.AuthAuthorityBootstrapServiceStub(channel)

            challenge_resp = await stub.InitBootstrapChallenge(
                bootstrap_pb2.BootstrapChallengeRequest(
                    entity_type=_to_proto_entity_type(payload["entity_type"]),
                    entity_id=payload["entity_id"],
                    key_id=payload["key_id"],
                    audience=payload["audience"],
                    ttl_sec=60,
                ),
                timeout=self._call_timeout_sec,
            )

            challenge = challenge_resp.challenge
            challenge_id = (challenge.challenge_id or "").strip()
            challenge_key_id = (challenge.key_id or "").strip() or payload["key_id"]
            if not challenge_id:
                raise RuntimeError("bootstrap challenge response missing challenge_id")

            auth_resp = await stub.AuthenticateBootstrap(
                bootstrap_pb2.BootstrapAuthenticateRequest(
                    challenge=challenge,
                    signed=bootstrap_pb2.SignedChallengeResponse(
                        challenge_id=challenge_id,
                        key_id=challenge_key_id,
                        signature_algorithm=(
                            bootstrap_pb2.SIGNATURE_ALGORITHM_ED25519
                        ),
                        signature=base64.b64encode(
                            f"bootstrap:{challenge_id}".encode("utf-8")
                        ).decode("utf-8"),
                        signed_at_ms=int(time.time() * 1000),
                    ),
                    scopes=["service:bootstrap"],
                    role="service",
                    require_downstream_token=False,
                ),
                timeout=self._call_timeout_sec,
            )

        stage = _normalize_bootstrap_stage(auth_resp.stage)
        if not stage:
            raise RuntimeError("bootstrap authenticate response missing stage")
        return BootstrapHandshakeResult(
            stage=stage,
            active_comm_key_id=(auth_resp.active_comm_key_id or "").strip(),
        )


def _to_proto_entity_type(raw: str) -> int:
    entity = (raw or "").strip().lower()
    if entity == "user":
        return bootstrap_pb2.ENTITY_TYPE_USER
    if entity == "device":
        return bootstrap_pb2.ENTITY_TYPE_DEVICE
    if entity == "service":
        return bootstrap_pb2.ENTITY_TYPE_SERVICE
    raise ValueError(f"unsupported bootstrap entity_type: {raw!r}")


def _normalize_bootstrap_stage(stage: int) -> str:
    if stage == bootstrap_pb2.BOOTSTRAP_STAGE_READY:
        return "ready"
    if stage == bootstrap_pb2.BOOTSTRAP_STAGE_UNINITIALIZED:
        return "uninitialized"
    if stage == bootstrap_pb2.BOOTSTRAP_STAGE_CHALLENGING:
        return "challenging"
    if stage == bootstrap_pb2.BOOTSTRAP_STAGE_AUTHENTICATING:
        return "authenticating"
    if stage == bootstrap_pb2.BOOTSTRAP_STAGE_UNSPECIFIED:
        return ""
    return (bootstrap_pb2.BootstrapStage.Name(stage) or "").strip().lower()
