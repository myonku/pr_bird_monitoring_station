from __future__ import annotations

from collections.abc import Awaitable, Callable
from uuid import UUID

from src.adapters.grpc.server_adapter import InMemoryGrpcRequest, InMemoryGrpcResponse
from src.models.auth.auth import IdentityContext
from src.models.auth.forwarded_auth import ForwardedAuthContext
from src.models.auth.internal_header_keys import (
    HEADER_AUTH_VERIFIED,
    HEADER_DOWNSTREAM_AUTH_VERIFY_MODE,
    HEADER_DOWNSTREAM_BINDING_TYPE,
    HEADER_DOWNSTREAM_GRANT_EXPIRES_AT,
    HEADER_DOWNSTREAM_GRANT_ISSUED_AT,
    HEADER_DOWNSTREAM_PRINCIPAL,
    HEADER_DOWNSTREAM_SESSION_ID,
    HEADER_DOWNSTREAM_SOURCE_SERVICE,
    HEADER_DOWNSTREAM_TARGET_SERVICE,
    HEADER_DOWNSTREAM_TOKEN_ID,
    HEADER_GATEWAY_ID,
    HEADER_REQUEST_ID,
    HEADER_SCOPES,
    HEADER_SOURCE_SERVICE,
    HEADER_TARGET_SERVICE,
    HEADER_TRACE_ID,
    HEADER_TRUE,
    HEADER_VERIFIED_ENTITY_ID,
    HEADER_VERIFIED_ENTITY_TYPE,
    HEADER_VERIFIED_GATEWAY_ID,
    HEADER_VERIFIED_PRINCIPAL_ID,
    HEADER_VERIFIED_REQUEST_ID,
    HEADER_VERIFIED_SCOPES,
    HEADER_VERIFIED_SESSION_ID,
    HEADER_VERIFIED_SOURCE_SERVICE,
    HEADER_VERIFIED_TARGET_SERVICE,
    HEADER_VERIFIED_TOKEN_ID,
    HEADER_VERIFIED_TRACE_ID,
)
from src.services.auth.forwarded_auth_verifier_svc import (
    AuthorityBackedForwardedAuthVerifier,
)

_NIL_UUID = UUID(int=0)


class ForwardedAuthUnaryInterceptor:
    """Inbound forwarded-auth interceptor contract skeleton.

    Notes:
    - This interceptor defines integration shape only.
    - Concrete verifier implementation is provided by external wiring.
    """

    def __init__(self, verifier: AuthorityBackedForwardedAuthVerifier):
        self._verifier = verifier

    async def __call__(
        self,
        request: InMemoryGrpcRequest,
        method: str,
        next_handler: Callable[[], Awaitable[InMemoryGrpcResponse]],
    ) -> InMemoryGrpcResponse:
        ctx = _build_forwarded_auth_context(request.headers)
        if ctx is None:
            return _unauthorized("forwarded auth context is required")

        try:
            verified = await self._verifier.verify_forwarded_auth(ctx)
        except Exception as exc:  # noqa: BLE001
            return _unauthorized(f"forwarded auth verify failed: {exc}")

        if not verified.allowed or verified.identity is None:
            reason = (
                verified.failure_reason if verified.failure_reason else "not allowed"
            )
            return _unauthorized(reason)

        _inject_verified_identity_headers(request.headers, verified.identity)
        return await next_handler()


def _build_forwarded_auth_context(
    headers: dict[str, str],
) -> ForwardedAuthContext | None:
    principal_id = _get_header_value(headers, HEADER_DOWNSTREAM_PRINCIPAL).strip()
    session_id = _get_header_value(headers, HEADER_DOWNSTREAM_SESSION_ID).strip()
    token_id = _get_header_value(headers, HEADER_DOWNSTREAM_TOKEN_ID).strip()

    if not principal_id or not session_id or not token_id:
        return None

    return ForwardedAuthContext(
        principal_id=principal_id,
        session_id=session_id,
        token_id=token_id,
        source_service=_get_header_value(
            headers, HEADER_DOWNSTREAM_SOURCE_SERVICE
        ).strip(),
        target_service=_get_header_value(
            headers, HEADER_DOWNSTREAM_TARGET_SERVICE
        ).strip(),
        binding_type=_get_header_value(headers, HEADER_DOWNSTREAM_BINDING_TYPE).strip(),
        gateway_id=_get_header_value(headers, HEADER_GATEWAY_ID).strip(),
        verify_mode=_get_header_value(
            headers, HEADER_DOWNSTREAM_AUTH_VERIFY_MODE
        ).strip(),
        grant_issued_at=_parse_int_header(headers, HEADER_DOWNSTREAM_GRANT_ISSUED_AT),
        grant_expires_at=_parse_int_header(headers, HEADER_DOWNSTREAM_GRANT_EXPIRES_AT),
        trace_id=_get_header_value(headers, HEADER_TRACE_ID).strip(),
        request_id=_get_header_value(headers, HEADER_REQUEST_ID).strip(),
    )


def _inject_verified_identity_headers(
    headers: dict[str, str], identity: IdentityContext
) -> None:
    headers[HEADER_AUTH_VERIFIED] = HEADER_TRUE

    if identity.principal_id:
        headers[HEADER_VERIFIED_PRINCIPAL_ID] = identity.principal_id
        headers[HEADER_DOWNSTREAM_PRINCIPAL] = identity.principal_id

    if identity.session_id and identity.session_id != _NIL_UUID:
        headers[HEADER_VERIFIED_SESSION_ID] = str(identity.session_id)
        headers[HEADER_DOWNSTREAM_SESSION_ID] = str(identity.session_id)

    if identity.token_id and identity.token_id != _NIL_UUID:
        headers[HEADER_VERIFIED_TOKEN_ID] = str(identity.token_id)
        headers[HEADER_DOWNSTREAM_TOKEN_ID] = str(identity.token_id)

    if identity.gateway_id:
        headers[HEADER_VERIFIED_GATEWAY_ID] = identity.gateway_id
        headers[HEADER_GATEWAY_ID] = identity.gateway_id

    if identity.source_service:
        headers[HEADER_VERIFIED_SOURCE_SERVICE] = identity.source_service
        headers[HEADER_SOURCE_SERVICE] = identity.source_service

    if identity.target_service:
        headers[HEADER_VERIFIED_TARGET_SERVICE] = identity.target_service
        headers[HEADER_TARGET_SERVICE] = identity.target_service

    if identity.trace_id:
        headers[HEADER_VERIFIED_TRACE_ID] = identity.trace_id
        headers[HEADER_TRACE_ID] = identity.trace_id

    if identity.request_id:
        headers[HEADER_VERIFIED_REQUEST_ID] = identity.request_id
        headers[HEADER_REQUEST_ID] = identity.request_id

    if identity.entity_type:
        headers[HEADER_VERIFIED_ENTITY_TYPE] = str(identity.entity_type)

    if identity.entity_id:
        headers[HEADER_VERIFIED_ENTITY_ID] = identity.entity_id

    if identity.scopes:
        scopes = ",".join(identity.scopes)
        headers[HEADER_VERIFIED_SCOPES] = scopes
        headers[HEADER_SCOPES] = scopes


def _unauthorized(reason: str) -> InMemoryGrpcResponse:
    return InMemoryGrpcResponse(
        status_code=401,
        payload=f"forwarded auth rejected: {reason}".encode("utf-8"),
        headers={"x-auth-error": "authority_revalidation_failed"},
    )


def _parse_int_header(headers: dict[str, str], key: str) -> int:
    raw = _get_header_value(headers, key).strip()
    if not raw:
        return 0
    try:
        return int(raw)
    except ValueError:
        return 0


def _get_header_value(headers: dict[str, str], key: str) -> str:
    direct = headers.get(key)
    if direct:
        return direct

    lower_key = key.lower()
    for hk, hv in headers.items():
        if hk.lower() == lower_key and hv:
            return hv

    return ""
