import sqlite3
from pathlib import Path


class SQLiteClient:
    """轻量 SQLite 客户端，供本地模块复用。"""

    def __init__(self, db_path: str, timeout_sec: float = 5.0) -> None:
        self._db_path = Path(db_path)
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._timeout_sec = timeout_sec

    @property
    def db_path(self) -> Path:
        return self._db_path

    def connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self._db_path), timeout=self._timeout_sec)
        conn.row_factory = sqlite3.Row
        return conn