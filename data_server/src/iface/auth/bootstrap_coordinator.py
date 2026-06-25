from abc import ABC, abstractmethod

from src.iface.common.local_credential_manager import ModuleCredentialSnapshot


class IBootstrapCoordinator(ABC):
    """data_server 引导认证生命周期编排。

    上层只依赖模块级协调面，不直接绑定 bootstrap / refresh 的底层 RPC 细节。
    """

    @abstractmethod
    async def ensure_module_ready(self) -> ModuleCredentialSnapshot | None:
        raise NotImplementedError

    @abstractmethod
    async def refresh_module_credential(self) -> ModuleCredentialSnapshot | None:
        raise NotImplementedError

    @abstractmethod
    async def revoke_module_credential(self, reason: str = "") -> None:
        raise NotImplementedError
