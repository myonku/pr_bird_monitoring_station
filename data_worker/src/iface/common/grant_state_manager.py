from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Literal

from src.models.auth.forwarded_auth import ForwardedAuthContext


GrantStatus = Literal["active", "used", "revoked", "expired"]


@dataclass(slots=True, kw_only=True)
class GrantStateRecord:
    grant_key: str

    principal_id: str
    session_id: str
    token_id: str

    gateway_id: str = ""
    source_service: str = ""
    target_service: str = ""

    status: GrantStatus = "active"

    issued_at: float = 0.0
    expires_at: float = 0.0
    used_at: float = 0.0
    updated_at: float = 0.0

    metadata: dict[str, str] = field(default_factory=dict)


class IGrantStateManager(ABC):
    """可选的下游授权状态管理端口。"""

    @abstractmethod
    async def save_grant(self, grant: ForwardedAuthContext) -> str:
        raise NotImplementedError

    @abstractmethod
    async def load_active_grant(self, token_id: str) -> GrantStateRecord | None:
        raise NotImplementedError

    @abstractmethod
    async def mark_grant_used(self, token_id: str, used_at: float) -> None:
        raise NotImplementedError

    @abstractmethod
    async def revoke_grant(self, token_id: str, reason: str = "") -> None:
        raise NotImplementedError

    @abstractmethod
    async def purge_expired_grants(self, before: float) -> int:
        raise NotImplementedError
