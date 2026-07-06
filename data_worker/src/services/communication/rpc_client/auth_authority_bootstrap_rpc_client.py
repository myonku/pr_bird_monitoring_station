# pyright: reportAttributeAccessIssue=false
from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from uuid import UUID
from typing import Any, cast

import grpc

from src.models.common.types import EntityType
from src.gen.auth.v1 import auth_authority_bootstrap_pb2 as bootstrap_pb2
from src.gen.auth.v1 import auth_authority_bootstrap_pb2_grpc as bootstrap_pb2_grpc
from src.models.auth.auth import (
    AuthMethod,
    IdentityContext,
    IssuedToken,
    Principal,
    Session,
    SessionStatus,
    TokenBundle,
    TokenClaims,
    TokenType,
)
from src.models.auth.bootstrap import (
    BootstrapAuthResult,
    BootstrapStage,
    ChallengePayload,
    ChallengeRequest,
)
from src.models.commsec.commsec import SignatureAlgorithm
from src.utils.crypto_utils import CryptoUtils


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
        challenge_request: ChallengeRequest,
        private_key_pem: bytes,
        role: str = "service",
        scopes: list[str] | None = None,
        require_downstream_token: bool = False,
    ) -> BootstrapAuthResult:
        if not self._endpoint:
            raise ValueError("auth authority endpoint is required")

        if challenge_request is None:
            raise ValueError("bootstrap challenge request is required")
        if not private_key_pem:
            raise ValueError("bootstrap private key is required")

        normalized_request = _normalize_challenge_request(challenge_request)
        resolved_scopes = [
            item.strip() for item in (scopes or ["service:bootstrap"]) if item.strip()
        ]
        resolved_role = (role or "").strip() or "service"

        async with grpc.aio.insecure_channel(self._endpoint) as channel:
            await asyncio.wait_for(
                channel.channel_ready(),
                timeout=self._dial_timeout_sec,
            )
            stub = bootstrap_pb2_grpc.AuthAuthorityBootstrapServiceStub(channel)

            challenge_resp = await stub.InitBootstrapChallenge(
                bootstrap_pb2.BootstrapChallengeRequest(
                    entity_type=_to_proto_entity_type(normalized_request.entity_type),
                    entity_id=normalized_request.entity_id,
                    key_id=normalized_request.key_id,
                    audience=normalized_request.audience,
                    client_id=normalized_request.client_id,
                    gateway_id=normalized_request.gateway_id,
                    source_ip=normalized_request.source_ip,
                    user_agent=normalized_request.user_agent,
                    request_id=normalized_request.request_id,
                    trace_id=normalized_request.trace_id,
                    ttl_sec=max(int(normalized_request.ttl_sec), 60),
                ),
                timeout=self._call_timeout_sec,
            )

            challenge = challenge_resp.challenge
            local_challenge = _to_local_challenge_payload(challenge)
            challenge_key_id = (
                challenge.key_id or ""
            ).strip() or normalized_request.key_id
            if not challenge_key_id:
                raise RuntimeError("bootstrap challenge response missing key_id")
            if (
                normalized_request.key_id
                and challenge_key_id != normalized_request.key_id
            ):
                raise RuntimeError(
                    "bootstrap challenge key_id does not match local key material"
                )

            signature_algorithm = (
                CryptoUtils.detect_signature_algorithm_from_private_key(private_key_pem)
            )
            signature_payload = CryptoUtils.build_bootstrap_signature_payload(
                local_challenge,
                key_id=challenge_key_id,
                entity_type=normalized_request.entity_type,
                entity_id=normalized_request.entity_id,
            )
            signed_at_ms = int(time.time() * 1000)

            auth_resp = await stub.AuthenticateBootstrap(
                bootstrap_pb2.BootstrapAuthenticateRequest(
                    challenge=challenge,
                    signed=bootstrap_pb2.SignedChallengeResponse(
                        challenge_id=str(local_challenge.challenge_id),
                        key_id=challenge_key_id,
                        signature_algorithm=_to_proto_signature_algorithm(
                            signature_algorithm
                        ),
                        signature=CryptoUtils.sign_by_algorithm(
                            signature_algorithm,
                            signature_payload,
                            private_key_pem,
                        ),
                        signed_at_ms=signed_at_ms,
                    ),
                    scopes=resolved_scopes,
                    role=resolved_role,
                    require_downstream_token=require_downstream_token,
                ),
                timeout=self._call_timeout_sec,
            )

        return _to_bootstrap_auth_result(
            auth_resp,
            challenge=local_challenge,
            request=normalized_request,
            role=resolved_role,
            scopes=resolved_scopes,
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
        return cast(BootstrapStage, "ready")
    if stage == bootstrap_pb2.BOOTSTRAP_STAGE_UNINITIALIZED:
        return cast(BootstrapStage, "uninitialized")
    if stage == bootstrap_pb2.BOOTSTRAP_STAGE_CHALLENGING:
        return cast(BootstrapStage, "challenging")
    if stage == bootstrap_pb2.BOOTSTRAP_STAGE_AUTHENTICATING:
        return cast(BootstrapStage, "authenticating")
    if stage == bootstrap_pb2.BOOTSTRAP_STAGE_UNSPECIFIED:
        return cast(BootstrapStage, "uninitialized")
    normalized = (bootstrap_pb2.BootstrapStage.Name(stage) or "").strip().lower()
    if normalized in {"uninitialized", "challenging", "authenticating", "ready"}:
        return cast(BootstrapStage, normalized)
    return cast(BootstrapStage, "uninitialized")


def _normalize_challenge_request(request: ChallengeRequest) -> ChallengeRequest:
    normalized = ChallengeRequest(
        entity_type=_normalize_entity_type(request.entity_type),
        entity_id=(request.entity_id or "").strip(),
        key_id=(request.key_id or "").strip(),
        audience=(request.audience or "").strip(),
        client_id=(request.client_id or "").strip(),
        gateway_id=(request.gateway_id or "").strip(),
        source_ip=(request.source_ip or "").strip(),
        user_agent=(request.user_agent or "").strip(),
        request_id=(request.request_id or "").strip(),
        trace_id=(request.trace_id or "").strip(),
        ttl_sec=max(int(request.ttl_sec), 1),
    )
    if not normalized.entity_id:
        raise ValueError("bootstrap entity_id is required")
    if not normalized.audience:
        raise ValueError("bootstrap audience is required")
    if not normalized.key_id:
        raise ValueError("bootstrap key_id is required")
    if not normalized.client_id:
        normalized.client_id = normalized.entity_id
    if not normalized.request_id:
        normalized.request_id = normalized.trace_id or normalized.entity_id
    if not normalized.trace_id:
        normalized.trace_id = normalized.request_id
    if not normalized.user_agent:
        normalized.user_agent = "data_worker-bootstrap-client"
    return normalized


def _normalize_entity_type(raw: str) -> EntityType:
    entity = (raw or "").strip().lower()
    if entity in {"user", "device", "service", "unknown"}:
        return cast(EntityType, entity)
    raise ValueError(f"unsupported bootstrap entity_type: {raw!r}")


def _to_local_challenge_payload(
    challenge: Any,
) -> ChallengePayload:
    challenge_id = _as_uuid((challenge.challenge_id or "").strip(), "challenge_id")
    return ChallengePayload(
        challenge_id=challenge_id,
        issuer=(challenge.issuer or "").strip(),
        audience=(challenge.audience or "").strip(),
        entity_type=_from_proto_entity_type(challenge.entity_type),
        entity_id=(challenge.entity_id or "").strip(),
        key_id=(challenge.key_id or "").strip(),
        nonce=(challenge.nonce or "").strip(),
        issued_at=float(challenge.issued_at_ms or 0) / 1000.0,
        expires_at=float(challenge.expires_at_ms or 0) / 1000.0,
    )


def _to_bootstrap_auth_result(
    auth_resp: Any,
    *,
    challenge: ChallengePayload,
    request: ChallengeRequest,
    role: str,
    scopes: list[str],
) -> BootstrapAuthResult:
    stage = _normalize_bootstrap_stage(int(auth_resp.stage))
    identity = _map_identity_context(
        auth_resp.identity,
        challenge=challenge,
        request=request,
        role=role,
        scopes=scopes,
    )
    session = _map_session(
        auth_resp.session,
        challenge=challenge,
        request=request,
        role=role,
        scopes=scopes,
    )
    tokens = _map_token_bundle(
        auth_resp.tokens,
        identity=identity,
        session=session,
        challenge=challenge,
        request=request,
    )
    active_comm_key_id = (auth_resp.active_comm_key_id or "").strip() or request.key_id
    issued_at = float(auth_resp.issued_at_ms or 0) / 1000.0
    expires_at = float(auth_resp.expires_at_ms or 0) / 1000.0
    if expires_at <= 0 and session is not None:
        expires_at = session.expires_at
    if issued_at <= 0 and identity is not None:
        issued_at = identity.issued_at

    return BootstrapAuthResult(
        stage=cast(BootstrapStage, stage),
        identity=identity,
        session=session,
        tokens=tokens,
        active_comm_key_id=active_comm_key_id,
        issued_at=issued_at,
        expires_at=expires_at,
    )


def _map_identity_context(
    proto_identity: Any | None,
    *,
    challenge: ChallengePayload,
    request: ChallengeRequest,
    role: str,
    scopes: list[str],
) -> IdentityContext | None:
    if proto_identity is None:
        return None

    principal = _map_principal(proto_identity.principal)
    issued_at = float(proto_identity.issued_at_ms or 0) / 1000.0
    expires_at = float(proto_identity.expires_at_ms or 0) / 1000.0
    return IdentityContext(
        principal=principal,
        entity_type=principal.entity_type,
        entity_id=principal.entity_id,
        principal_id=_principal_id(principal),
        session_id=_as_uuid(proto_identity.session_id, "session_id"),
        token_id=_as_uuid(proto_identity.token_id, "token_id"),
        token_family_id=_as_uuid(proto_identity.token_family_id, "token_family_id"),
        token_type="access",
        role=(proto_identity.role or role).strip() or role,
        scopes=list(proto_identity.scopes) if proto_identity.scopes else list(scopes),
        auth_method=_from_proto_auth_method(proto_identity.auth_method),
        source_ip=(proto_identity.source_ip or request.source_ip or "").strip(),
        client_id=(proto_identity.client_id or request.client_id or "").strip(),
        gateway_id=(proto_identity.gateway_id or request.gateway_id or "").strip(),
        source_service=(
            proto_identity.source_service or request.client_id or ""
        ).strip(),
        target_service=(
            proto_identity.target_service or challenge.audience or ""
        ).strip(),
        user_agent=(request.user_agent or "").strip(),
        request_id=(proto_identity.request_id or request.request_id or "").strip(),
        trace_id=(
            proto_identity.trace_id or request.trace_id or request.request_id or ""
        ).strip(),
        issued_at=issued_at,
        expires_at=expires_at,
    )


def _map_session(
    proto_session: Any | None,
    *,
    challenge: ChallengePayload,
    request: ChallengeRequest,
    role: str,
    scopes: list[str],
) -> Session | None:
    if proto_session is None:
        return None

    principal = _map_principal(proto_session.principal)
    created_at = float(proto_session.created_at_ms or 0) / 1000.0
    updated_at = float(proto_session.updated_at_ms or 0) / 1000.0
    last_seen_at = float(proto_session.last_seen_at_ms or 0) / 1000.0
    last_verified_at = float(proto_session.last_verified_at_ms or 0) / 1000.0
    next_refresh_at = float(proto_session.next_refresh_at_ms or 0) / 1000.0
    expires_at = float(proto_session.expires_at_ms or 0) / 1000.0
    revoked_at = float(proto_session.revoked_at_ms or 0) / 1000.0

    session_id = _as_uuid(proto_session.session_id, "session_id")
    token_family_id = _as_uuid(proto_session.token_family_id, "token_family_id")
    status = _from_proto_session_status(proto_session.status)
    auth_method = _from_proto_auth_method(proto_session.auth_method)
    entity_type = _from_proto_entity_type(proto_session.entity_type)
    entity_id = (proto_session.entity_id or request.entity_id or "").strip()
    principal_id = (
        proto_session.principal_id or _principal_id(principal) or ""
    ).strip()
    scope_snapshot = (
        list(proto_session.scope_snapshot)
        if proto_session.scope_snapshot
        else list(scopes)
    )
    role_snapshot = (proto_session.role_snapshot or role or "").strip() or role

    return Session(
        id=session_id,
        principal=principal,
        entity_type=entity_type,
        entity_id=entity_id,
        principal_id=principal_id,
        status=status,
        auth_method=auth_method,
        created_by_ip=(proto_session.created_by_ip or request.source_ip or "").strip(),
        last_seen_ip=(proto_session.last_seen_ip or request.source_ip or "").strip(),
        user_agent=(proto_session.user_agent or request.user_agent or "").strip(),
        client_id=(proto_session.client_id or request.client_id or "").strip(),
        gateway_id=(proto_session.gateway_id or request.gateway_id or "").strip(),
        scope_snapshot=scope_snapshot,
        role_snapshot=role_snapshot,
        token_family_id=token_family_id,
        created_at=created_at,
        updated_at=updated_at,
        last_seen_at=last_seen_at,
        last_verified_at=last_verified_at,
        next_refresh_at=next_refresh_at,
        expires_at=expires_at,
        revoked_at=revoked_at,
        version=int(proto_session.version or 0),
    )


def _map_token_bundle(
    proto_bundle: Any | None,
    *,
    identity: IdentityContext | None,
    session: Session | None,
    challenge: ChallengePayload,
    request: ChallengeRequest,
) -> TokenBundle | None:
    if proto_bundle is None:
        return None

    access_token = _map_issued_token(
        proto_bundle.access_token,
        token_type="access",
        claims=_build_token_claims(
            identity=identity,
            token_type="access",
            challenge=challenge,
            request=request,
        ),
    )
    refresh_token = _map_issued_token(
        proto_bundle.refresh_token,
        token_type="refresh",
    )
    downstream_token = _map_issued_token(
        proto_bundle.downstream_token,
        token_type="downstream",
    )
    return TokenBundle(
        access_token=access_token,
        refresh_token=refresh_token,
        downstream_token=downstream_token,
    )


def _map_issued_token(
    proto_token: Any | None,
    *,
    token_type: TokenType,
    claims: TokenClaims | None = None,
) -> IssuedToken | None:
    if proto_token is None:
        return None

    normalized_token_type = _from_proto_token_type(proto_token.token_type)
    if normalized_token_type is None:
        # TOKEN_TYPE_UNSPECIFIED → 未颁发的 token，视为空
        return None
    if normalized_token_type != token_type:
        token_type = normalized_token_type

    return IssuedToken(
        raw=(proto_token.raw or "").strip(),
        type=token_type,
        ttl_sec=int(proto_token.ttl_sec or 0),
        claims=claims,
    )


def _build_token_claims(
    *,
    identity: IdentityContext | None,
    token_type: TokenType,
    challenge: ChallengePayload,
    request: ChallengeRequest,
) -> TokenClaims | None:
    if identity is None:
        return None

    family_id = identity.token_family_id
    token_id = identity.token_id if token_type == "access" else identity.token_id
    parent_id = UUID(int=0)
    return TokenClaims(
        issuer=challenge.issuer or request.client_id,
        audience=challenge.audience or request.audience,
        subject=identity.principal_id,
        type=token_type,
        entity_type=identity.entity_type,
        entity_id=identity.entity_id,
        principal_id=identity.principal_id,
        session_id=identity.session_id,
        token_id=token_id,
        family_id=family_id,
        parent_id=parent_id,
        role=identity.role,
        scopes=list(identity.scopes),
        auth_method=identity.auth_method,
        client_id=identity.client_id,
        gateway_id=identity.gateway_id,
        source_service=identity.source_service,
        target_service=identity.target_service,
        issued_at=identity.issued_at,
        expires_at=identity.expires_at,
    )


def _map_principal(proto_principal: Any | None) -> Principal:
    if proto_principal is None:
        raise RuntimeError("bootstrap response missing principal")
    entity_type = _from_proto_entity_type(proto_principal.entity_type)
    entity_id = (proto_principal.entity_id or "").strip()
    if not entity_id:
        raise RuntimeError("bootstrap response missing principal entity_id")
    return Principal(entity_type=entity_type, entity_id=entity_id)


def _principal_id(principal: Principal) -> str:
    return principal.principal_id()


def _from_proto_entity_type(value: int) -> EntityType:
    if value == bootstrap_pb2.ENTITY_TYPE_USER:
        return cast(EntityType, "user")
    if value == bootstrap_pb2.ENTITY_TYPE_DEVICE:
        return cast(EntityType, "device")
    if value == bootstrap_pb2.ENTITY_TYPE_SERVICE:
        return cast(EntityType, "service")
    raise ValueError(f"unsupported bootstrap entity_type: {value}")


def _from_proto_token_type(value: int) -> TokenType | None:
    if value == bootstrap_pb2.TOKEN_TYPE_ACCESS:
        return "access"
    if value == bootstrap_pb2.TOKEN_TYPE_REFRESH:
        return "refresh"
    if value == bootstrap_pb2.TOKEN_TYPE_DOWNSTREAM:
        return "downstream"
    if value == bootstrap_pb2.TOKEN_TYPE_SERVICE:
        return "service"
    if value == bootstrap_pb2.TOKEN_TYPE_UNSPECIFIED:
        return None
    raise ValueError(f"unsupported bootstrap token_type: {value}")


def _from_proto_session_status(value: int) -> SessionStatus:
    if value == bootstrap_pb2.SESSION_STATUS_ACTIVE:
        return "active"
    if value == bootstrap_pb2.SESSION_STATUS_REVOKED:
        return "revoked"
    if value == bootstrap_pb2.SESSION_STATUS_EXPIRED:
        return "expired"
    if value == bootstrap_pb2.SESSION_STATUS_BLOCKED:
        return "blocked"
    if value == bootstrap_pb2.SESSION_STATUS_UNSPECIFIED:
        return "active"
    raise ValueError(f"unsupported bootstrap session status: {value}")


def _from_proto_auth_method(value: int | str) -> AuthMethod:
    if isinstance(value, str):
        # proto enum 可能以字符串形式返回
        normalized = value.strip().lower()
        if normalized in ("password", "device_secret", "service_secret", "refresh_token", "token_exchange"):
            return cast(AuthMethod, normalized)
        return "service_secret"
    if value == bootstrap_pb2.AUTH_METHOD_PASSWORD:
        return "password"
    if value == bootstrap_pb2.AUTH_METHOD_DEVICE_SECRET:
        return "device_secret"
    if value == bootstrap_pb2.AUTH_METHOD_SERVICE_SECRET:
        return "service_secret"
    if value == bootstrap_pb2.AUTH_METHOD_REFRESH_TOKEN:
        return "refresh_token"
    if value == bootstrap_pb2.AUTH_METHOD_TOKEN_EXCHANGE:
        return "token_exchange"
    if value == bootstrap_pb2.AUTH_METHOD_UNSPECIFIED:
        return "service_secret"
    raise ValueError(f"unsupported bootstrap auth_method: {value}")


def _to_proto_signature_algorithm(value: SignatureAlgorithm) -> int:
    if value == "ed25519":
        return bootstrap_pb2.SIGNATURE_ALGORITHM_ED25519
    if value == "ecdsa_p256_sha256":
        return bootstrap_pb2.SIGNATURE_ALGORITHM_ECDSA_P256_SHA256
    if value == "rsa_pss_sha256":
        return bootstrap_pb2.SIGNATURE_ALGORITHM_RSA_PSS_SHA256
    raise ValueError(f"unsupported signature algorithm: {value}")


def _as_uuid(raw: str, field_name: str) -> UUID:
    value = (raw or "").strip()
    if not value:
        raise RuntimeError(f"bootstrap response missing {field_name}")
    return UUID(value)
