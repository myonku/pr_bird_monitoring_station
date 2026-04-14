from abc import ABC, abstractmethod

from dataclasses import dataclass, field

from src.models.auth.auth import IdentityContext, Session, TokenBundle
from src.models.auth.bootstrap import BootstrapStage


@dataclass(slots=True, kw_only=True)
class ModuleCredentialSnapshot:
    """data_worker 本模块凭证快照。"""

    principal_id: str
    stage: BootstrapStage = "uninitialized"

    identity: IdentityContext | None = None
    session: Session | None = None
    tokens: TokenBundle | None = None

    active_comm_key_id: str = ""

    issued_at: float = 0.0
    expires_at: float = 0.0
    updated_at: float = 0.0

    metadata: dict[str, str] = field(default_factory=dict)


class ILocalCredentialManager(ABC):
    """本模块凭证快照管理接口，负责管理本地凭证快照、对本模块提供运行期所需的凭证信息。"""

    @abstractmethod
    async def save_bootstrap_credential(self, snapshot: ModuleCredentialSnapshot) -> str:
        """写入 bootstrap 成功后的凭证快照，返回存储键。"""
        raise NotImplementedError

    @abstractmethod
    async def load_active_credential(self, principal_id: str) -> ModuleCredentialSnapshot | None:
        """读取主体当前可用凭证快照。"""
        raise NotImplementedError

    @abstractmethod
    async def mark_credential_expired(self, principal_id: str, reason: str = "") -> None:
        """标记主体凭证为过期。"""
        raise NotImplementedError

    @abstractmethod
    async def revoke_credential(self, principal_id: str, reason: str = "") -> None:
        """撤销主体凭证并清理可用状态。"""
        raise NotImplementedError
