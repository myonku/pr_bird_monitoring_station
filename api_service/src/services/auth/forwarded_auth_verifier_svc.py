from __future__ import annotations

import time
from typing import cast
from uuid import UUID

from src.models.auth.auth import IdentityContext, Principal, Session
from src.models.auth.auth_contract import SessionValidateRequest
from src.models.auth.forwarded_auth import (
    ForwardedAuthContext,
    ForwardedAuthVerificationResult,
)
from src.models.auth.internal_header_keys import (
    DOWNSTREAM_AUTH_VERIFY_MODE_AUTHORITY_DOUBLE_CHECK,
)
from src.models.common.entry import EntityType
from src.services.auth.auth_authority import IAuthAuthorityClient

_NIL_UUID = UUID(int=0)
_ALLOWED_ENTITY_TYPES = {"user", "service", "device"}


class AuthorityBackedForwardedAuthVerifier:
    """Strict authority-backed verifier for gateway forwarded-auth revalidation."""

    def __init__(
        self,
        authority_client: IAuthAuthorityClient,
        service_name: str = "api_service",
    ):
        self._authority_client = authority_client
        self._service_name = service_name.strip() or "api_service"

    async def verify_forwarded_auth(
        self,
        req: ForwardedAuthContext,
    ) -> ForwardedAuthVerificationResult:
        principal_id = req.principal_id.strip()
        if not principal_id:
            return _reject("principal_id is required")
        parsed_principal = _parse_principal(principal_id)
        if parsed_principal is None:
            return _reject("principal_id must be <entity_type>:<entity_id>")
        entity_type, entity_id = parsed_principal

        verify_mode = req.verify_mode.strip().lower()
        if verify_mode != DOWNSTREAM_AUTH_VERIFY_MODE_AUTHORITY_DOUBLE_CHECK:
            return _reject(
                "verify_mode must be authority-double-check"
            )

        source_service = req.source_service.strip()
        if not source_service:
            return _reject("source_service is required")

        target_service = req.target_service.strip()
        if not target_service:
            return _reject("target_service is required")
        if target_service != self._service_name:
            return _reject("target service mismatch")

        gateway_id = req.gateway_id.strip()
        if not gateway_id:
            return _reject("gateway_id is required")

        if req.grant_issued_at <= 0 or req.grant_expires_at <= 0:
            return _reject("grant window is required")
        if req.grant_issued_at >= req.grant_expires_at:
            return _reject("invalid grant window")
        now_ts = int(time.time())
        if req.grant_expires_at <= now_ts:
            return _reject("grant expired")

        session_id = _parse_uuid(req.session_id)
        token_id = _parse_uuid(req.token_id)
        if session_id is None:
            return _reject("invalid session_id")
        if token_id is None:
            return _reject("invalid token_id")

        try:
            session = await self._authority_client.validate_session(
                SessionValidateRequest(
                    session_id=session_id,
                    principal_id=principal_id,
                    require_active=True,
                    min_version=0,
                )
            )
        except Exception as exc:  # noqa: BLE001
            return _reject(f"authority validate_session failed: {exc}")

        if session is None:
            return _reject("session not active")
        if session.id != session_id:
            return _reject("session_id mismatch")
        if session.principal_id != principal_id:
            return _reject("principal mismatch")
        if session.expires_at > 0 and session.expires_at <= float(now_ts):
            return _reject("session expired")

        identity = _build_identity(
            req=req,
            session=session,
            entity_type=entity_type,
            entity_id=entity_id,
            token_id=token_id,
            source_service=source_service,
            target_service=target_service,
            gateway_id=gateway_id,
        )
        return ForwardedAuthVerificationResult(
            allowed=True,
            identity=identity,
            session=session,
        )


def _build_identity(
    req: ForwardedAuthContext,
    session: Session,
    entity_type: EntityType,
    entity_id: str,
    token_id: UUID,
    source_service: str,
    target_service: str,
    gateway_id: str,
) -> IdentityContext:
    issued_at = float(req.grant_issued_at)
    expires_at = _resolve_identity_expires_at(session, req.grant_expires_at)

    return IdentityContext(
        principal=Principal(entity_type=entity_type, entity_id=entity_id),
        entity_type=entity_type,
        entity_id=entity_id,
        principal_id=req.principal_id,
        session_id=session.id,
        token_id=token_id,
        token_family_id=session.token_family_id,
        token_type="access",
        role=session.role_snapshot,
        scopes=list(session.scope_snapshot),
        auth_method=session.auth_method,
        source_ip="",
        client_id=session.client_id,
        gateway_id=gateway_id,
        source_service=source_service,
        target_service=target_service,
        user_agent="",
        request_id=req.request_id,
        trace_id=req.trace_id,
        secure_channel_id=_NIL_UUID,
        secure_channel_status="",
        cipher_suite="",
        issued_at=issued_at,
        expires_at=expires_at,
    )


def _parse_principal(principal_id: str) -> tuple[EntityType, str] | None:
    raw = principal_id.strip()
    if ":" not in raw:
        return None

    prefix, entity_id = raw.split(":", 1)
    prefix = prefix.strip().lower()
    entity_id = entity_id.strip()
    if prefix not in _ALLOWED_ENTITY_TYPES or not entity_id:
        return None

    return cast(EntityType, prefix), entity_id


def _parse_uuid(raw: str) -> UUID | None:
    text = raw.strip()
    if not text:
        return None
    try:
        return UUID(text)
    except ValueError:
        return None


def _reject(reason: str) -> ForwardedAuthVerificationResult:
    return ForwardedAuthVerificationResult(
        allowed=False,
        failure_reason=reason,
    )


def _resolve_identity_expires_at(session: Session, grant_expires_at: int) -> float:
    grant_exp = float(grant_expires_at)
    if session.expires_at <= 0:
        return grant_exp
    return min(session.expires_at, grant_exp)
