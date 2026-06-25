# pyright: reportAttributeAccessIssue=false
from __future__ import annotations

import asyncio

import grpc

from src.gen.auth.v1 import auth_authority_bootstrap_pb2 as bootstrap_pb2
from src.gen.auth.v1 import auth_authority_token_refresh_pb2 as refresh_pb2
from src.gen.auth.v1 import auth_authority_token_refresh_pb2_grpc as refresh_pb2_grpc
from src.iface.auth.authority_client import TokenRefreshRequest
from src.models.auth.auth import IssuedToken, TokenBundle, TokenType


class AuthAuthorityTokenRefreshRPCClient:
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

    async def execute_refresh_token_bundle(
        self,
        req: TokenRefreshRequest,
    ) -> TokenBundle:
        if not self._endpoint:
            raise ValueError("auth authority endpoint is required")
        if req is None:
            raise ValueError("token refresh request is required")
        if not (req.refresh_token or "").strip():
            raise ValueError("refresh_token is required")

        async with grpc.aio.insecure_channel(self._endpoint) as channel:
            await asyncio.wait_for(
                channel.channel_ready(),
                timeout=self._dial_timeout_sec,
            )
            stub = refresh_pb2_grpc.AuthAuthorityTokenRefreshServiceStub(channel)
            response = await stub.RefreshTokenBundle(
                refresh_pb2.TokenRefreshRequest(
                    refresh_token=req.refresh_token,
                    client_id=req.client_id,
                    gateway_id=req.gateway_id,
                    source_ip=req.source_ip,
                    user_agent=req.user_agent,
                    request_id=req.request_id,
                    trace_id=req.trace_id,
                ),
                timeout=self._call_timeout_sec,
            )

        return _to_local_token_bundle(response)


def _to_local_token_bundle(
    response: bootstrap_pb2.TokenBundle | None,
) -> TokenBundle:
    if response is None:
        return TokenBundle()

    return TokenBundle(
        access_token=_to_local_issued_token(response.access_token),
        refresh_token=_to_local_issued_token(response.refresh_token),
        downstream_token=_to_local_issued_token(response.downstream_token),
    )


def _to_local_issued_token(
    token: bootstrap_pb2.IssuedToken | None,
) -> IssuedToken | None:
    if token is None:
        return None

    token_type = _from_proto_token_type(token.token_type)
    if token_type is None:
        return None
    return IssuedToken(
        raw=(token.raw or "").strip(),
        type=token_type,
        ttl_sec=int(token.ttl_sec or 0),
    )


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
    raise ValueError(f"unsupported refresh token_type: {value}")
