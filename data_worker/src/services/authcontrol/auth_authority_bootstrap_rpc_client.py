from __future__ import annotations

import asyncio
import base64
import time
from dataclasses import dataclass

import grpc
from google.protobuf import json_format
from google.protobuf import struct_pb2


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

            init_call = channel.unary_unary(
                BOOTSTRAP_INIT_METHOD,
                request_serializer=_serialize_struct,
                response_deserializer=_deserialize_struct,
            )
            challenge_resp = await init_call(
                _dict_to_struct(payload),
                timeout=self._call_timeout_sec,
            )
            challenge_envelope = _struct_to_dict(challenge_resp)
            challenge = challenge_envelope.get("challenge")
            if not isinstance(challenge, dict):
                challenge = challenge_envelope
            challenge_id = str(challenge.get("challenge_id", "")).strip()
            challenge_key_id = str(challenge.get("key_id", "")).strip() or payload["key_id"]
            if not challenge_id:
                raise RuntimeError("bootstrap challenge response missing challenge_id")

            auth_call = channel.unary_unary(
                BOOTSTRAP_AUTH_METHOD,
                request_serializer=_serialize_struct,
                response_deserializer=_deserialize_struct,
            )
            auth_req = {
                "challenge": challenge,
                "signed": {
                    "challenge_id": challenge_id,
                    "key_id": challenge_key_id,
                    "signature_algorithm": "ed25519",
                    "signature": base64.b64encode(
                        f"bootstrap:{challenge_id}".encode("utf-8")
                    ).decode("utf-8"),
                    "signed_at_ms": int(time.time() * 1000),
                },
                "scopes": ["service:bootstrap"],
                "role": "service",
                "require_downstream_token": False,
            }
            auth_resp = await auth_call(
                _dict_to_struct(auth_req),
                timeout=self._call_timeout_sec,
            )

        auth_payload = _struct_to_dict(auth_resp)
        stage = _normalize_bootstrap_stage(str(auth_payload.get("stage", "")).strip())
        if not stage:
            raise RuntimeError("bootstrap authenticate response missing stage")
        return BootstrapHandshakeResult(
            stage=stage,
            active_comm_key_id=str(auth_payload.get("active_comm_key_id", "")).strip(),
        )


def _dict_to_struct(payload: dict) -> struct_pb2.Struct:
    msg = struct_pb2.Struct()
    msg.update(payload)
    return msg


def _struct_to_dict(payload: struct_pb2.Struct) -> dict:
    return json_format.MessageToDict(payload, preserving_proto_field_name=True)


def _serialize_struct(payload: struct_pb2.Struct) -> bytes:
    return payload.SerializeToString()


def _deserialize_struct(raw: bytes) -> struct_pb2.Struct:
    msg = struct_pb2.Struct()
    msg.ParseFromString(raw)
    return msg


def _normalize_bootstrap_stage(raw: str) -> str:
    stage = (raw or "").strip().lower()
    if stage in {"ready", "bootstrap_stage_ready", "4"}:
        return "ready"
    if stage in {"uninitialized", "bootstrap_stage_uninitialized", "1"}:
        return "uninitialized"
    if stage in {"challenging", "bootstrap_stage_challenging", "2"}:
        return "challenging"
    if stage in {"authenticating", "bootstrap_stage_authenticating", "3"}:
        return "authenticating"
    return stage
