from __future__ import annotations

from collections.abc import Awaitable, Callable
from urllib.parse import parse_qsl

from src.adapters.grpc.server_adapter import InMemoryGrpcRequest, InMemoryGrpcResponse
from src.models.auth.internal_assertion import (
    InternalAssertionVerifyRequest,
    VerifiedInternalIdentity,
)
from src.models.auth.internal_header_keys import (
    HEADER_AUTH_VERIFIED,
    HEADER_DOWNSTREAM_PRINCIPAL,
    HEADER_DOWNSTREAM_SESSION_ID,
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
    HEADER_VERIFIED_JTI,
    HEADER_VERIFIED_KEY_ID,
    HEADER_VERIFIED_PRINCIPAL_ID,
    HEADER_VERIFIED_REQUEST_ID,
    HEADER_VERIFIED_SCOPES,
    HEADER_VERIFIED_SESSION_ID,
    HEADER_VERIFIED_SOURCE_SERVICE,
    HEADER_VERIFIED_TARGET_SERVICE,
    HEADER_VERIFIED_TOKEN_ID,
    HEADER_VERIFIED_TRACE_ID,
)
from src.models.sys.config import InternalAssertionConfig
from src.services.auth.internal_assertion_verifier_svc import InternalAssertionVerifier


class InternalAssertionUnaryInterceptor:
    """入站内部断言拦截器。"""

    def __init__(
        self,
        verifier: InternalAssertionVerifier,
        config: InternalAssertionConfig | None = None,
    ):
        self._verifier = verifier
        self._config = (config or verifier.config).normalized()

    async def __call__(
        self,
        request: InMemoryGrpcRequest,
        method: str,
        next_handler: Callable[[], Awaitable[InMemoryGrpcResponse]],
    ) -> InMemoryGrpcResponse:
        if not self._config.enabled:
            return await next_handler()

        assertion = _get_header_value(request.headers, self._config.header_name)
        if not assertion:
            if self._config.required:
                return _unauthorized("internal assertion is required")
            return await next_handler()

        request_path = (
            _get_header_value(request.headers, "x-request-path")
            or _get_header_value(request.headers, "x-path")
            or ""
        )
        raw_query = _get_header_value(request.headers, "x-request-query")
        query_dict = (
            dict(parse_qsl(raw_query, keep_blank_values=True)) if raw_query else {}
        )

        try:
            verified_identity = await self._verifier.verify_request(
                InternalAssertionVerifyRequest(
                    method=method,
                    path=request_path,
                    query=query_dict,
                    body=request.payload,
                    headers=request.headers,
                )
            )
        except ValueError as exc:
            return _unauthorized(str(exc))

        _inject_verified_headers(request.headers, verified_identity)
        return await next_handler()


def _inject_verified_headers(
    headers: dict[str, str],
    identity: VerifiedInternalIdentity,
) -> None:
    headers[HEADER_AUTH_VERIFIED] = HEADER_TRUE

    if identity.principal_id:
        headers[HEADER_VERIFIED_PRINCIPAL_ID] = identity.principal_id
        headers[HEADER_DOWNSTREAM_PRINCIPAL] = identity.principal_id

    if identity.session_id:
        headers[HEADER_VERIFIED_SESSION_ID] = identity.session_id
        headers[HEADER_DOWNSTREAM_SESSION_ID] = identity.session_id

    if identity.token_id:
        headers[HEADER_VERIFIED_TOKEN_ID] = identity.token_id
        headers[HEADER_DOWNSTREAM_TOKEN_ID] = identity.token_id

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

    if identity.jti:
        headers[HEADER_VERIFIED_JTI] = identity.jti

    if identity.key_id:
        headers[HEADER_VERIFIED_KEY_ID] = identity.key_id

    if identity.entity_type:
        headers[HEADER_VERIFIED_ENTITY_TYPE] = identity.entity_type

    if identity.entity_id:
        headers[HEADER_VERIFIED_ENTITY_ID] = identity.entity_id

    if identity.scopes:
        headers[HEADER_VERIFIED_SCOPES] = ",".join(identity.scopes)
        headers[HEADER_SCOPES] = ",".join(identity.scopes)


def _unauthorized(reason: str) -> InMemoryGrpcResponse:
    return InMemoryGrpcResponse(
        status_code=401,
        payload=f"internal assertion rejected: {reason}".encode("utf-8"),
        headers={"x-auth-error": "internal_assertion_invalid"},
    )


def _get_header_value(headers: dict[str, str], key: str) -> str:
    direct = headers.get(key)
    if direct:
        return direct

    lower_key = key.lower()
    for hk, hv in headers.items():
        if hk.lower() == lower_key and hv:
            return hv

    return ""
