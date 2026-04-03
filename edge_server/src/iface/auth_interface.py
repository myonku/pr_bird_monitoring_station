from abc import ABC, abstractmethod
from collections.abc import Sequence

from src.models.auth.auth import (
    EdgeTokenBundle,
    LocalTrustMaterial,
    TokenType,
)
from src.models.auth.auth_contract import (
    EdgeAuthHeaders,
    EdgeAuthState,
    RefreshTokenRequest,
    TokenVerificationResult,
)
from src.models.auth.bootstrap import BootstrapChallenge, SignedBootstrapProof


class ISecretKeyManager(ABC):
    """本地密钥能力接口，提供密钥管理功能。"""

    @abstractmethod
    def get_local_trust_material(self) -> LocalTrustMaterial:
        raise NotImplementedError

    @abstractmethod
    def get_public_key_pem(self) -> bytes:
        raise NotImplementedError

    @abstractmethod
    def get_private_key_pem(self) -> bytes:
        raise NotImplementedError


class IEdgeGatewayAuthClient(ABC):
    """edge-to-gateway 认证 API 的协议端口。

    Gateway 负责将这些请求转发给认证中心。
    """

    @abstractmethod
    def init_bootstrap_challenge(
        self, device_id: str, key_id: str
    ) -> BootstrapChallenge:
        raise NotImplementedError

    @abstractmethod
    def authenticate_bootstrap(self, proof: SignedBootstrapProof) -> EdgeAuthState:
        raise NotImplementedError

    @abstractmethod
    def refresh_tokens(self, req: RefreshTokenRequest) -> EdgeTokenBundle | None:
        raise NotImplementedError

    @abstractmethod
    def verify_token(
        self,
        raw_token: str,
        expected_types: Sequence[TokenType] | None = None,
        allow_expired_skew_sec: int = 0,
    ) -> TokenVerificationResult:
        raise NotImplementedError

    @abstractmethod
    def revoke(self, token_id: str | None, family_id: str | None) -> None:
        raise NotImplementedError


class IEdgeAuthStateStore(ABC):
    """本地持久化认证状态的接口，供认证协调器使用。
    认证协调器负责维护和更新认证状态，并通过此接口进行持久化存储。"""

    @abstractmethod
    def load(self) -> EdgeAuthState | None:
        raise NotImplementedError

    @abstractmethod
    def save(self, state: EdgeAuthState) -> None:
        raise NotImplementedError

    @abstractmethod
    def clear(self, reason: str = "") -> None:
        raise NotImplementedError


class IEdgeAuthTransportCoordinator(ABC):
    """高层认证协调器接口，定义了边缘认证的核心流程和策略。
    认证协调器负责管理认证状态、处理认证事件，并与网关进行交互以完成认证和授权流程。"""

    @abstractmethod
    def ensure_ready(self, now_ts: float | None = None) -> EdgeAuthState:
        """Ensure edge side has a valid session + access token pair."""
        raise NotImplementedError

    @abstractmethod
    def get_auth_headers(self, now_ts: float | None = None) -> EdgeAuthHeaders:
        """Provide auth headers for business HTTP calls to gateway."""
        raise NotImplementedError

    @abstractmethod
    def on_unauthorized(
        self, status_code: int, response_text: str = ""
    ) -> EdgeAuthState:
        """Handle 401/403 and trigger re-bootstrap or refresh strategy."""
        raise NotImplementedError

    @abstractmethod
    def logout(self, reason: str = "") -> None:
        raise NotImplementedError
