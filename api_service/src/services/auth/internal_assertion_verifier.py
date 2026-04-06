from typing import Protocol

from src.models.auth.internal_assertion import (
    InternalAssertionVerifyRequest,
    VerifiedInternalIdentity,
)


class IInternalAssertionVerifier(Protocol):
    """内部断言验证器协议。"""

    async def verify_request(
        self,
        req: InternalAssertionVerifyRequest,
    ) -> VerifiedInternalIdentity:
        ...
