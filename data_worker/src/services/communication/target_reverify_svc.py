from __future__ import annotations

from src.iface.communication.authority_client import IAuthAuthorityClient
from src.iface.auth.target_reverify import ITargetReverify
from src.models.auth.forwarded_auth import (
    ForwardedAuthContext,
    ForwardedAuthVerificationResult,
)


class TargetReverifyService(ITargetReverify):
    """目标服务侧二次认证复核最小实现。"""

    def __init__(self, *, authority_client: IAuthAuthorityClient | None) -> None:
        self._authority_client = authority_client

    async def reverify_forwarded_context(
        self,
        forwarded: ForwardedAuthContext,
    ) -> ForwardedAuthVerificationResult:
        if forwarded is None:
            raise ValueError("forwarded auth context is required")
        if self._authority_client is None:
            raise RuntimeError("target reverify dependencies are required")
        return await self._authority_client.reverify_forwarded_context(forwarded)
