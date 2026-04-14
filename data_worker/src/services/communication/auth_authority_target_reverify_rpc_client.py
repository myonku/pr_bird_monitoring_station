# pyright: reportAttributeAccessIssue=false
from __future__ import annotations

import asyncio

import grpc
from src.gen.auth.v1 import auth_authority_target_reverify_pb2 as target_reverify_pb2
from src.gen.auth.v1 import (
    auth_authority_target_reverify_pb2_grpc as target_reverify_pb2_grpc,
)
from src.models.auth.forwarded_auth import (
    ForwardedAuthContext,
    ForwardedAuthVerificationResult,
)


TARGET_REVERIFY_METHOD = (
    "/bms.auth.v1.AuthAuthorityTargetReverifyService/ReverifyForwardedContext"
)


class AuthAuthorityTargetReverifyRPCClient:
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

    async def reverify_forwarded_context(
        self,
        ctx: ForwardedAuthContext,
    ) -> ForwardedAuthVerificationResult:
        if not self._endpoint:
            raise ValueError("auth authority endpoint is required")
        if ctx is None:
            raise ValueError("forwarded auth context is required")

        async with grpc.aio.insecure_channel(self._endpoint) as channel:
            await asyncio.wait_for(
                channel.channel_ready(),
                timeout=self._dial_timeout_sec,
            )
            stub = target_reverify_pb2_grpc.AuthAuthorityTargetReverifyServiceStub(
                channel
            )
            response = await stub.ReverifyForwardedContext(
                target_reverify_pb2.ForwardedAuthContext(
                    principal_id=(ctx.principal_id or "").strip(),
                    session_id=(ctx.session_id or "").strip(),
                    token_id=(ctx.token_id or "").strip(),
                    source_service=(ctx.source_service or "").strip(),
                    target_service=(ctx.target_service or "").strip(),
                    gateway_id=(ctx.gateway_id or "").strip(),
                    verify_mode=(ctx.verify_mode or "").strip(),
                    grant_issued_at_ms=int(ctx.grant_issued_at or 0),
                    grant_expires_at_ms=int(ctx.grant_expires_at or 0),
                    trace_id=(ctx.trace_id or "").strip(),
                    request_id=(ctx.request_id or "").strip(),
                ),
                timeout=self._call_timeout_sec,
            )

        return ForwardedAuthVerificationResult(
            allowed=bool(response.allowed),
            failure_reason=(response.failure_reason or "").strip(),
        )
