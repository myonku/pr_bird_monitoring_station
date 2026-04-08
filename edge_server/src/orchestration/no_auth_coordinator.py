from typing import cast

from src.iface.auth_interface import IEdgeAuthCoordinator
from src.models.auth.auth import TokenType
from src.models.auth.auth_contract import EdgeAuthHeaders, EdgeAuthState
from src.utils.runtime_logger import RuntimeEventLogger


class NoAuthEdgeAuthCoordinator(IEdgeAuthCoordinator):
    """无认证模式协调器：保留接口形态，但不执行真实认证流程。"""

    _EMPTY_STATE = EdgeAuthState(
        stage="ready",
        session=None,
        tokens=None,
        failure_reason="",
    )
    _EMPTY_HEADERS = EdgeAuthHeaders(
        authorization="",
        session_id="",
        token_id="",
        token_type=cast(TokenType, ""),
        principal_id="",
        scopes=[""],
    )

    def __init__(self, event_logger: RuntimeEventLogger | None = None) -> None:
        self._event_logger = event_logger
        self._log("no_auth_mode_initialized")

    def _log(self, event: str, details: dict | None = None) -> None:
        if self._event_logger is not None:
            self._event_logger.emit(stage="auth", event=event, details=details)

    def ensure_startup_ready(self, now_ts: float | None = None) -> EdgeAuthState:
        return self._EMPTY_STATE

    def ensure_ready(self, now_ts: float | None = None) -> EdgeAuthState:
        return self._EMPTY_STATE

    def get_auth_headers(self, now_ts: float | None = None) -> EdgeAuthHeaders:
        return self._EMPTY_HEADERS

    def on_unauthorized(self, status_code: int, response_text: str = "") -> EdgeAuthState:
        self._log(
            "unauthorized_ignored_no_auth_mode",
            {
                "status_code": status_code,
            },
        )
        return self._EMPTY_STATE

    def logout(self, reason: str = "") -> None:
        self._log("logout_ignored_no_auth_mode", {"reason": reason})
