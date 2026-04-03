import json
import time
from dataclasses import asdict
from typing import Any

from src.iface.auth_interface import IEdgeAuthStateStore
from src.local_storage.sqlite_client import SQLiteClient
from src.models.auth.auth import EdgeSession, EdgeToken, EdgeTokenBundle
from src.models.auth.auth_contract import EdgeAuthState
from src.models.auth.auth import AuthStage, SessionStatus, TokenType


class SQLiteEdgeAuthStateStore(IEdgeAuthStateStore):
    """认证状态 SQLite 持久化实现。

    目标：在边缘侧以单机 SQLite 同时承担“缓存 + 持久化”职责，
    为认证协调器提供可恢复的 session/token 状态。
    """

    def __init__(
        self,
        db_path: str | None = None,
        sqlite_client: SQLiteClient | None = None,
    ) -> None:
        if sqlite_client is None:
            sqlite_client = SQLiteClient(db_path=db_path or "data/edge_auth.sqlite3")
        self._sqlite = sqlite_client
        self._init_db()

    def _connect(self):
        return self._sqlite.connect()

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS edge_auth_state (
                    state_id INTEGER PRIMARY KEY CHECK(state_id = 1),
                    stage TEXT NOT NULL,
                    failure_reason TEXT NOT NULL DEFAULT '',
                    session_json TEXT,
                    access_token_json TEXT,
                    refresh_token_json TEXT,
                    updated_at_ms INTEGER NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS edge_auth_events (
                    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_type TEXT NOT NULL,
                    reason TEXT NOT NULL DEFAULT '',
                    created_at_ms INTEGER NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_edge_auth_events_created
                ON edge_auth_events (created_at_ms)
                """
            )
            conn.commit()

    @staticmethod
    def _to_json(value: dict[str, Any] | None) -> str | None:
        if value is None:
            return None
        return json.dumps(value, ensure_ascii=False)

    @staticmethod
    def _from_json(raw: str | None) -> dict[str, Any] | None:
        if not raw:
            return None
        data = json.loads(raw)
        if not isinstance(data, dict):
            raise ValueError("unexpected json payload for edge auth state")
        return data

    @staticmethod
    def _as_str_list(value: Any) -> list[str]:
        if not isinstance(value, list):
            return []
        return [str(item) for item in value]

    @staticmethod
    def _to_session(value: dict[str, Any] | None) -> EdgeSession | None:
        if value is None:
            return None
        status = value.get("status", "active")
        if status not in SessionStatus:
            status = "active"
        return EdgeSession(
            session_id=str(value.get("session_id", "")),
            principal_id=str(value.get("principal_id", "")),
            device_id=str(value.get("device_id", "")),
            status=status,
            issued_at=float(value.get("issued_at", 0.0)),
            expires_at=float(value.get("expires_at", 0.0)),
            token_family_id=str(value.get("token_family_id", "")),
            last_verified_at=float(value.get("last_verified_at", 0.0)),
        )

    @staticmethod
    def _to_token(value: dict[str, Any] | None) -> EdgeToken | None:
        if value is None:
            return None
        token_type = value.get("token_type", "access")
        if token_type not in TokenType:
            token_type = "access"
        return EdgeToken(
            raw=str(value.get("raw", "")),
            token_type=token_type,
            token_id=str(value.get("token_id", "")),
            family_id=str(value.get("family_id", "")),
            session_id=str(value.get("session_id", "")),
            issued_at=float(value.get("issued_at", 0.0)),
            expires_at=float(value.get("expires_at", 0.0)),
            scopes=SQLiteEdgeAuthStateStore._as_str_list(value.get("scopes", [])),
            role=str(value.get("role", "")),
        )

    @classmethod
    def _row_to_state(cls, row) -> EdgeAuthState:
        session = cls._to_session(cls._from_json(row["session_json"]))
        access_token = cls._to_token(cls._from_json(row["access_token_json"]))
        refresh_token = cls._to_token(cls._from_json(row["refresh_token_json"]))

        token_bundle = None
        if access_token is not None or refresh_token is not None:
            token_bundle = EdgeTokenBundle(
                access_token=access_token,
                refresh_token=refresh_token,
            )
        stage = row["stage"]
        if stage not in AuthStage:
            stage = "uninitialized"
        return EdgeAuthState(
            stage=stage,
            session=session,
            tokens=token_bundle,
            failure_reason=str(row["failure_reason"] or ""),
        )

    @staticmethod
    def _is_token_usable(
        token: EdgeToken | None, now_ts: float, skew_sec: int = 0
    ) -> bool:
        if token is None:
            return False
        return now_ts + max(0, skew_sec) < token.expires_at

    def load(self) -> EdgeAuthState | None:
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT
                    stage,
                    failure_reason,
                    session_json,
                    access_token_json,
                    refresh_token_json
                FROM edge_auth_state
                WHERE state_id = 1
                """
            ).fetchone()

        if row is None:
            return None
        return self._row_to_state(row)

    def save(self, state: EdgeAuthState) -> None:
        session_json = self._to_json(
            asdict(state.session) if state.session is not None else None
        )

        access_token = state.tokens.access_token if state.tokens is not None else None
        refresh_token = state.tokens.refresh_token if state.tokens is not None else None
        access_token_json = self._to_json(
            asdict(access_token) if access_token is not None else None
        )
        refresh_token_json = self._to_json(
            asdict(refresh_token) if refresh_token is not None else None
        )
        now_ms = int(time.time() * 1000)

        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO edge_auth_state (
                    state_id,
                    stage,
                    failure_reason,
                    session_json,
                    access_token_json,
                    refresh_token_json,
                    updated_at_ms
                ) VALUES (1, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(state_id) DO UPDATE SET
                    stage = excluded.stage,
                    failure_reason = excluded.failure_reason,
                    session_json = excluded.session_json,
                    access_token_json = excluded.access_token_json,
                    refresh_token_json = excluded.refresh_token_json,
                    updated_at_ms = excluded.updated_at_ms
                """,
                (
                    state.stage,
                    state.failure_reason,
                    session_json,
                    access_token_json,
                    refresh_token_json,
                    now_ms,
                ),
            )
            conn.execute(
                """
                INSERT INTO edge_auth_events (event_type, reason, created_at_ms)
                VALUES (?, ?, ?)
                """,
                ("save", state.failure_reason or "", now_ms),
            )
            conn.commit()

    def clear(self, reason: str = "") -> None:
        now_ms = int(time.time() * 1000)
        with self._connect() as conn:
            conn.execute("DELETE FROM edge_auth_state WHERE state_id = 1")
            conn.execute(
                """
                INSERT INTO edge_auth_events (event_type, reason, created_at_ms)
                VALUES (?, ?, ?)
                """,
                ("clear", reason, now_ms),
            )
            conn.commit()

    def get_session(self) -> EdgeSession | None:
        state = self.load()
        if state is None:
            return None
        return state.session

    def get_token_bundle(self) -> EdgeTokenBundle | None:
        state = self.load()
        if state is None:
            return None
        return state.tokens

    def get_access_token(self) -> EdgeToken | None:
        bundle = self.get_token_bundle()
        if bundle is None:
            return None
        return bundle.access_token

    def get_refresh_token(self) -> EdgeToken | None:
        bundle = self.get_token_bundle()
        if bundle is None:
            return None
        return bundle.refresh_token

    def get_active_access_token(
        self,
        now_ts: float | None = None,
        skew_sec: int = 30,
    ) -> EdgeToken | None:
        token = self.get_access_token()
        ts = now_ts if now_ts is not None else time.time()
        if not self._is_token_usable(token, ts, skew_sec=skew_sec):
            return None
        return token
