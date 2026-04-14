from abc import ABC, abstractmethod

from src.models.auth.forwarded_auth import (
    ForwardedAuthContext,
    ForwardedAuthVerificationResult,
)


class ITargetReverify(ABC):
    """目标侧转发认证复验能力。

    下游接口调用：
      - authcontrol.IAuthAuthorityClient.reverify_forwarded_context
            - common.IGrantStateManager.load_active_grant（可选路径）
            - common.IGrantStateManager.mark_grant_used（可选路径）
    """

    @abstractmethod
    async def reverify_forwarded_context(
        self,
        forwarded: ForwardedAuthContext,
    ) -> ForwardedAuthVerificationResult:
        raise NotImplementedError
