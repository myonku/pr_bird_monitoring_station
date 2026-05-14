import time
import uuid
from collections.abc import Callable

from src.iface.auth_interface import (
    IEdgeAuthCoordinator,
    IEdgeAuthStateStore,
    IEdgeGatewayAuthClient,
    ISecretKeyManager,
)
from src.models.auth.auth import EdgeSession, EdgeToken, EdgeTokenBundle, SignatureAlgorithm
from src.models.auth.auth_contract import (
    EdgeAuthHeaders,
    EdgeAuthState,
    RefreshTokenRequest,
)
from src.models.auth.bootstrap import (
    BootstrapAuthenticateRequest,
    SignedBootstrapProof,
)
from src.utils.crypto_utils import CryptoUtils
from src.utils.runtime_logger import RuntimeEventLogger


class EdgeAuthCoordinator(IEdgeAuthCoordinator):
    """边缘认证流程协调器。

    职责：
    - 管理本地认证状态（session/token）
    - 调用网关认证客户端完成 bootstrap/refresh/revoke
    - 对业务层暴露认证头与未授权恢复策略

    非职责：
    - 不负责业务事件上传
    - 不负责 HTTP 通信实现细节
    """

    def __init__(
        self,
        *,
        key_manager: ISecretKeyManager,
        gateway_auth_client: IEdgeGatewayAuthClient,
        state_store: IEdgeAuthStateStore,
        access_token_skew_sec: int = 30,
        refresh_request_builder: Callable[[str], RefreshTokenRequest] | None = None,
        event_logger: RuntimeEventLogger | None = None,
    ) -> None:
        self._key_manager = key_manager
        self._gateway_auth_client = gateway_auth_client
        self._state_store = state_store
        self._access_token_skew_sec = max(0, access_token_skew_sec)
        self._refresh_request_builder = (
            refresh_request_builder or self._default_refresh_request
        )
        self._event_logger = event_logger

    def _log(self, event: str, details: dict | None = None) -> None:
        if self._event_logger is not None:
            self._event_logger.emit(stage="auth", event=event, details=details)

    @staticmethod
    def _now(now_ts: float | None = None) -> float:
        return now_ts if now_ts is not None else time.time()

    @staticmethod
    def _is_token_usable(token: EdgeToken | None, now_ts: float, skew_sec: int) -> bool:
        if token is None:
            return False
        return now_ts + max(0, skew_sec) < token.expires_at

    @staticmethod
    def _is_session_active(session: EdgeSession | None, now_ts: float) -> bool:
        if session is None:
            return False
        if session.status != "active":
            return False
        return now_ts < session.expires_at

    def _is_state_ready(self, state: EdgeAuthState | None, now_ts: float) -> bool:
        if state is None or state.tokens is None:
            return False
        if not self._is_session_active(state.session, now_ts):
            return False
        return self._is_token_usable(
            state.tokens.access_token,
            now_ts,
            self._access_token_skew_sec,
        )

    def _is_long_lived_ready(self, state: EdgeAuthState | None, now_ts: float) -> bool:
        if state is None or state.tokens is None:
            return False
        if not self._is_session_active(state.session, now_ts):
            return False
        return self._is_token_usable(state.tokens.refresh_token, now_ts, skew_sec=0)

    @staticmethod
    def _default_refresh_request(refresh_token: str) -> RefreshTokenRequest:
        request_id = str(uuid.uuid4())
        return RefreshTokenRequest(
            refresh_token=refresh_token,
            client_id="edge-server",
            gateway_id="gateway",
            source_ip="0.0.0.0",
            user_agent="edge-server-auth-coordinator",
            request_id=request_id,
            trace_id=request_id,
        )

    def _build_refreshed_state(
        self,
        *,
        previous_state: EdgeAuthState,
        refreshed_bundle: EdgeTokenBundle,
        now_ts: float,
    ) -> EdgeAuthState:
        merged_bundle = self._merge_token_bundle(
            previous_state.tokens,
            refreshed_bundle,
        )
        session = previous_state.session
        if session is not None:
            updated_session_id = session.session_id
            if (
                merged_bundle.access_token is not None
                and merged_bundle.access_token.session_id
            ):
                updated_session_id = merged_bundle.access_token.session_id

            updated_family_id = session.token_family_id
            if (
                merged_bundle.refresh_token is not None
                and merged_bundle.refresh_token.family_id
            ):
                updated_family_id = merged_bundle.refresh_token.family_id

            session = EdgeSession(
                session_id=updated_session_id,
                principal_id=session.principal_id,
                device_id=session.device_id,
                status=session.status,
                issued_at=session.issued_at,
                expires_at=session.expires_at,
                token_family_id=updated_family_id,
                last_verified_at=now_ts,
            )

        return EdgeAuthState(
            stage="ready",
            session=session,
            tokens=merged_bundle,
            failure_reason="",
        )

    @staticmethod
    def _prefer_text(primary: str | None, fallback: str | None) -> str:
        normalized_primary = (primary or "").strip()
        if normalized_primary:
            return normalized_primary
        return (fallback or "").strip()

    @staticmethod
    def _prefer_positive_number(primary: float, fallback: float) -> float:
        if primary > 0:
            return primary
        if fallback > 0:
            return fallback
        return 0.0

    def _merge_token(
        self,
        previous: EdgeToken | None,
        refreshed: EdgeToken | None,
    ) -> EdgeToken | None:
        if refreshed is None:
            return previous
        if previous is None:
            return refreshed

        return EdgeToken(
            raw=self._prefer_text(refreshed.raw, previous.raw),
            token_type=refreshed.token_type or previous.token_type,
            token_id=self._prefer_text(refreshed.token_id, previous.token_id),
            family_id=self._prefer_text(refreshed.family_id, previous.family_id),
            session_id=self._prefer_text(refreshed.session_id, previous.session_id),
            issued_at=self._prefer_positive_number(
                refreshed.issued_at,
                previous.issued_at,
            ),
            expires_at=self._prefer_positive_number(
                refreshed.expires_at,
                previous.expires_at,
            ),
            scopes=refreshed.scopes or previous.scopes,
            role=self._prefer_text(refreshed.role, previous.role),
        )

    def _merge_token_bundle(
        self,
        previous_bundle: EdgeTokenBundle | None,
        refreshed_bundle: EdgeTokenBundle,
    ) -> EdgeTokenBundle:
        previous_access = (
            previous_bundle.access_token if previous_bundle is not None else None
        )
        previous_refresh = (
            previous_bundle.refresh_token if previous_bundle is not None else None
        )
        return EdgeTokenBundle(
            access_token=self._merge_token(previous_access, refreshed_bundle.access_token),
            refresh_token=self._merge_token(previous_refresh, refreshed_bundle.refresh_token),
        )

    def _try_refresh(
        self,
        *,
        state: EdgeAuthState,
        now_ts: float,
    ) -> EdgeAuthState | None:
        if state.tokens is None:
            return None

        refresh_token = state.tokens.refresh_token
        if refresh_token is None:
            return None
        if not refresh_token.raw.strip():
            return None
        if not self._is_token_usable(refresh_token, now_ts, skew_sec=0):
            return None

        request_payload = self._refresh_request_builder(refresh_token.raw)
        try:
            refreshed_bundle = self._gateway_auth_client.refresh_token_bundle(
                request_payload
            )
        except Exception:
            self._log("refresh_failed")
            return None
        if refreshed_bundle is None or refreshed_bundle.access_token is None:
            self._log("refresh_empty_result")
            return None

        refreshed_state = self._build_refreshed_state(
            previous_state=state,
            refreshed_bundle=refreshed_bundle,
            now_ts=now_ts,
        )
        self._state_store.save(refreshed_state)
        self._log("refresh_succeeded")
        return refreshed_state

    def _bootstrap(self, now_ts: float) -> EdgeAuthState:
        trust_material = self._key_manager.get_local_trust_material()
        challenge = self._gateway_auth_client.request_bootstrap_challenge(
            trust_material.device_id,
            trust_material.key_id,
            audience="gateway",
        )

        proof = self._build_bootstrap_proof(
            challenge=challenge,
            trust_material=trust_material,
            now_ts=now_ts,
        )

        auth_request = BootstrapAuthenticateRequest(
            challenge=challenge,
            signed=proof,
            scopes=[],
            role="device",
            require_downstream_token=False,
        )

        state = self._gateway_auth_client.submit_bootstrap_proof(auth_request)

        normalized = self._normalize_bootstrap_state(state)
        self._state_store.save(normalized)
        self._log(
            "bootstrap_succeeded",
            {
                "session_id": normalized.session.session_id if normalized.session else "",
                "stage": normalized.stage,
            },
        )
        return normalized

    @staticmethod
    def _normalize_bootstrap_state(state: EdgeAuthState) -> EdgeAuthState:
        if state.stage != "ready":
            reason = state.failure_reason or f"unexpected bootstrap stage: {state.stage}"
            raise ValueError(reason)
        if state.session is None:
            raise ValueError("bootstrap response missing session")
        if state.tokens is None:
            raise ValueError("bootstrap response missing token bundle")
        if state.tokens.access_token is None:
            raise ValueError("bootstrap response missing access token")
        if state.tokens.refresh_token is None:
            raise ValueError("bootstrap response missing refresh token")

        return EdgeAuthState(
            stage="ready",
            session=state.session,
            tokens=state.tokens,
            failure_reason="",
        )

    def _build_bootstrap_signature(
        self,
        *,
        challenge,
        challenge_key_id: str,
        entity_type: str,
        entity_id: str,
        signature_algorithm: SignatureAlgorithm,
        private_key_pem: bytes,
    ) -> str:
        payload = CryptoUtils.build_bootstrap_signature_payload(
            challenge,
            key_id=challenge_key_id,
            entity_type=entity_type,
            entity_id=entity_id,
        )
        return CryptoUtils.sign_by_algorithm(
            signature_algorithm,
            payload,
            private_key_pem,
        )

    def _build_bootstrap_proof(
        self,
        *,
        challenge,
        trust_material,
        now_ts: float,
    ) -> SignedBootstrapProof:

        challenge_key_id = challenge.key_id or trust_material.key_id
        if trust_material.key_id and challenge_key_id != trust_material.key_id:
            raise ValueError(
                "challenge key_id does not match local key material: "
                f"challenge={challenge_key_id}, local={trust_material.key_id}"
            )

        entity_type = challenge.entity_type or "device"
        entity_id = challenge.entity_id or trust_material.device_id
        private_key_pem = self._key_manager.get_private_key_pem()
        signature_algorithm = CryptoUtils.detect_signature_algorithm_from_private_key(
            private_key_pem
        )
        signature = self._build_bootstrap_signature(
            challenge=challenge,
            challenge_key_id=challenge_key_id,
            entity_type=entity_type,
            entity_id=entity_id,
            signature_algorithm=signature_algorithm,
            private_key_pem=private_key_pem,
        )
        return SignedBootstrapProof(
            challenge_id=challenge.challenge_id,
            device_id=trust_material.device_id,
            key_id=challenge_key_id,
            signature=signature,
            signature_algorithm=signature_algorithm,
            signed_at=now_ts,
        )

    def ensure_ready(self, now_ts: float | None = None) -> EdgeAuthState:
        ts = self._now(now_ts)
        state = self._state_store.load()
        if state is None:
            return self._bootstrap(ts)

        if self._is_state_ready(state, ts):
            return state

        refreshed = self._try_refresh(state=state, now_ts=ts)
        if refreshed is not None and self._is_state_ready(refreshed, ts):
            return refreshed

        return self._bootstrap(ts)

    def ensure_startup_ready(self, now_ts: float | None = None) -> EdgeAuthState:
        """full_development 启动门禁：至少确保长期令牌可用；缺失时执行 bootstrap。"""

        ts = self._now(now_ts)
        state = self._state_store.load()
        if state is not None and self._is_long_lived_ready(state, ts):
            self._log("startup_gate_ready")
            return state
        self._log("startup_gate_bootstrap_required")
        return self._bootstrap(ts)

    def get_auth_headers(self, now_ts: float | None = None) -> EdgeAuthHeaders:
        state = self.ensure_ready(now_ts=now_ts)
        if (
            state.session is None
            or state.tokens is None
            or state.tokens.access_token is None
        ):
            raise ValueError("edge auth state is not ready for header generation")

        access = state.tokens.access_token
        return EdgeAuthHeaders(
            authorization=f"Bearer {access.raw}",
            session_id=state.session.session_id,
            token_id=access.token_id,
            token_type=access.token_type,
            principal_id=state.session.principal_id,
            scopes=access.scopes,
        )

    def on_unauthorized(
        self,
        status_code: int,
        response_text: str = "",
    ) -> EdgeAuthState:
        ts = self._now()
        state = self._state_store.load()
        if status_code not in (401, 403):
            return self.ensure_ready(now_ts=ts)

        self._log(
            "unauthorized_received",
            {
                "status_code": status_code,
            },
        )

        if state is not None:
            refreshed = self._try_refresh(state=state, now_ts=ts)
            if refreshed is not None and self._is_state_ready(refreshed, ts):
                return refreshed

        reason = f"unauthorized({status_code})"
        if response_text:
            reason = f"{reason}: {response_text}"
        self._state_store.clear(reason=reason)
        self._log("unauthorized_rebootstrap", {"reason": reason})
        return self._bootstrap(ts)

    def logout(self, reason: str = "") -> None:
        state = self._state_store.load()
        token_id: str | None = None
        family_id: str | None = None

        if state is not None and state.tokens is not None:
            refresh_token = state.tokens.refresh_token
            access_token = state.tokens.access_token

            if refresh_token is not None:
                token_id = refresh_token.token_id
                family_id = refresh_token.family_id
            elif access_token is not None:
                token_id = access_token.token_id
                family_id = access_token.family_id

        try:
            self._gateway_auth_client.revoke_tokens(token_id=token_id, family_id=family_id)
        finally:
            self._state_store.clear(reason=reason or "logout")
