from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from src.iface.common.local_credential_manager import ModuleCredentialSnapshot
from src.models.auth.bootstrap import ChallengeRequest


@dataclass(slots=True, kw_only=True)
class BootstrapEnsureReadyRequest:
    challenge_request: ChallengeRequest
    role: str = ""
    scopes: list[str] = field(default_factory=list)
    require_downstream_token: bool = False


class IBootstrapCoordinator(ABC):
    """data_worker 引导认证生命周期编排。

    下游接口调用：
      - common.IKeyManager.get_private_key_ref / get_public_key
      - communication.IAuthAuthorityClient.init_bootstrap_challenge / authenticate_bootstrap / refresh_token_bundle / revoke_token
      - common.ILocalCredentialManager.save_bootstrap_credential / load_active_credential / mark_credential_expired / revoke_credential
    """

    @abstractmethod
    async def ensure_module_ready(self, req: BootstrapEnsureReadyRequest) -> ModuleCredentialSnapshot:
        raise NotImplementedError

    @abstractmethod
    async def refresh_module_credential(self, principal_id: str) -> ModuleCredentialSnapshot:
        raise NotImplementedError

    @abstractmethod
    async def revoke_module_credential(self, principal_id: str, reason: str = "") -> None:
        raise NotImplementedError
