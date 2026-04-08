from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from collections.abc import Iterable, Sequence
from typing import Any

import aiomysql
from src.models.sys.config import MySQLConfig, ProjectConfig
from src.utils.circuit_breaker import CircuitBreaker, CircuitOpenError



class MySQLClient:
    """
    MySQL 异步客户端，封装了连接池和基本的数据库操作。
    为业务/元数据服务和OutBox提供服务引用。
    """
    def __init__(self, cfg: ProjectConfig):
        if not cfg.mysql:
            raise RuntimeError("MySQL config not provided")
        self.cfg = cfg
        self.pool: aiomysql.Pool | None = None
        self.circuit = CircuitBreaker("mysql", cfg.mysql.CIRCUITBREAKER)

    async def is_connected(self) -> bool:
        return self.pool is not None and not self.pool.closed

    def _parse_conn_str(self, conn_str: str) -> dict[str, str]:
        """解析形如 'Server=host;Database=db;User Id=u;Password=p;Port=3306' 的连接字符串。
        注意：简单分号分割，不支持带分号的密码。
        """
        parts = [p for p in conn_str.split(";") if p.strip()]
        kv: dict[str, str] = {}
        for p in parts:
            if "=" not in p:
                continue
            k, v = p.split("=", 1)
            kv[k.strip().lower()] = v.strip()
        return kv

    async def _connect_single(
        self,
        host: str,
        port: int,
        user: str,
        password: str,
        db: str,
        **pool_kwargs: Any,
    ) -> None:
        pool_defaults: dict[str, Any] = {
            "host": host,
            "port": port,
            "user": user,
            "password": password,
            "db": db,
            "autocommit": False,
            "minsize": 1,
            "maxsize": 10,
            "connect_timeout": 5,
            "charset": "utf8mb4",
        }
        pool_defaults.update(pool_kwargs)
        self.pool = await aiomysql.create_pool(**pool_defaults)

    async def connect(self, **pool_kwargs: Any):
        """基于配置连接：
        - 若提供多个 URI（HOSTS），按顺序尝试连接到第一个可用实例。
        - 若仅单个 URI，则直接连接。
        - 建议生产中使用 MySQL Router/ProxySQL 暴露单一入口。
        """
        mysql_cfg: MySQLConfig | None
        if isinstance(self.cfg, ProjectConfig):
            mysql_cfg = getattr(self.cfg, "mysql", None)
        else:
            mysql_cfg = self.cfg

        if not mysql_cfg:
            raise RuntimeError("MySQL config not provided")

        uris = mysql_cfg.mysql_uris()
        if not uris:
            raise RuntimeError("MySQL connection strings are empty")

        last_err: Exception | None = None
        for conn_str in uris:
            kv = self._parse_conn_str(conn_str)
            host = kv.get("server") or kv.get("host") or ""
            db = kv.get("database") or kv.get("db") or ""
            user = kv.get("user id") or kv.get("uid") or kv.get("user") or ""
            password = kv.get("password") or kv.get("pwd") or ""
            port_s = kv.get("port") or ""
            try:
                port = int(port_s) if port_s else (mysql_cfg.PORT or 3306)
                await self._connect_single(
                    host=host,
                    port=port,
                    user=user,
                    password=password,
                    db=db,
                    **pool_kwargs,
                )
                return
            except Exception as e:  # 尝试下一个
                last_err = e
                print(f"连接失败，尝试下一个 MySQL 实例: {conn_str} | {e}")
                continue

        raise ConnectionError(f"所有 MySQL 实例连接失败: {last_err}")

    async def disconnect(self):
        print("正在关闭MySQL连接")
        if self.pool:
            self.pool.close()
            await self.pool.wait_closed()
            self.pool = None

    @asynccontextmanager
    async def connection(self) -> AsyncGenerator[aiomysql.Connection, None]:
        """提供一个异步上下文管理器，获取一个数据库连接。"""
        if not self.pool:
            raise RuntimeError("MySQL connection pool not initialized")
        async with self.pool.acquire() as conn:
            yield conn

    @asynccontextmanager
    async def cursor(
        self, conn: aiomysql.Connection | None = None
    ) -> AsyncGenerator[aiomysql.Cursor, None]:
        """提供一个异步上下文管理器，获取一个 DictCursor 游标。"""
        if conn:
            async with conn.cursor(aiomysql.DictCursor) as cur:
                yield cur
        else:
            async with self.connection() as conn:
                async with conn.cursor(aiomysql.DictCursor) as cur:
                    yield cur


class MySQLBaseDAO:
    """MySQL DAO 基类。

    设计目标：
    - 用统一的条件构造器覆盖不同表的大多数基础 CRUD。
    - 支持按主键/按条件/按 IN 集合查询与更新，减少重复写 SQL。
    """

    def __init__(
        self,
        mysql_db: MySQLClient,
        table_name: str,
        primary_key: str = "id",
        allowed_columns: set[str] | None = None,
        default_select_columns: Sequence[str] | None = None,
    ):
        self.mysql_db = mysql_db
        self.table_name = table_name
        self.primary_key = primary_key
        self.allowed_columns = allowed_columns
        self.default_select_columns = tuple(default_select_columns or ("*",))

    def _assert_column_name(self, column: str) -> str:
        if not column:
            raise ValueError("column name cannot be empty")
        if self.allowed_columns is not None and column not in self.allowed_columns:
            raise ValueError(f"column '{column}' is not allowed for table {self.table_name}")
        return column

    def _columns_sql(self, columns: Sequence[str] | None = None) -> str:
        use_columns = list(columns or self.default_select_columns)
        if use_columns == ["*"]:
            return "*"
        return ", ".join(self._assert_column_name(c) for c in use_columns)

    def _build_in_clause(self, values: Sequence[Any]) -> tuple[str, tuple[Any, ...]]:
        if not values:
            return "(NULL)", tuple()
        placeholders = ", ".join(["%s"] * len(values))
        return f"({placeholders})", tuple(values)

    def _build_where(
        self,
        filters: dict[str, Any] | None = None,
        in_filters: dict[str, Sequence[Any]] | None = None,
        like_filters: dict[str, str] | None = None,
    ) -> tuple[str, tuple[Any, ...]]:
        clauses: list[str] = []
        params: list[Any] = []

        for key, value in (filters or {}).items():
            col = self._assert_column_name(key)
            if value is None:
                clauses.append(f"{col} IS NULL")
            else:
                clauses.append(f"{col} = %s")
                params.append(value)

        for key, values in (in_filters or {}).items():
            col = self._assert_column_name(key)
            if not values:
                clauses.append("1 = 0")
                continue
            in_sql, in_params = self._build_in_clause(list(values))
            clauses.append(f"{col} IN {in_sql}")
            params.extend(in_params)

        for key, pattern in (like_filters or {}).items():
            col = self._assert_column_name(key)
            clauses.append(f"{col} LIKE %s")
            params.append(pattern)

        if not clauses:
            return "", tuple()
        return " WHERE " + " AND ".join(clauses), tuple(params)

    def _build_order_by(self, order_by: Sequence[str] | None = None) -> str:
        if not order_by:
            return ""

        items: list[str] = []
        for raw_col in order_by:
            direction = "ASC"
            col = raw_col
            if raw_col.startswith("-"):
                direction = "DESC"
                col = raw_col[1:]
            safe_col = self._assert_column_name(col)
            items.append(f"{safe_col} {direction}")
        return " ORDER BY " + ", ".join(items)

    async def _execute(self, query: str, params: tuple[Any, ...] = ()) -> int:
        async def _do_exec() -> int:
            async with self.mysql_db.cursor() as cur:
                await cur.execute(query, params)
                conn: Any = cur.connection
                if conn is not None:
                    await conn.commit()
                return int(cur.rowcount)

        try:
            return int(await self.mysql_db.circuit.call(_do_exec))
        except CircuitOpenError as e:
            print(f"MySQL circuit open, fast-fail execute: {query} | {params} | {e}")
            raise
        except Exception as e:
            print(f"MySQL query failed: {query} | {params} | {e}")
            raise

    async def _executemany(self, query: str, params: Iterable[tuple[Any, ...]]) -> int:
        async def _do_exec_many() -> int:
            async with self.mysql_db.cursor() as cur:
                await cur.executemany(query, list(params))
                conn: Any = cur.connection
                if conn is not None:
                    await conn.commit()
                return int(cur.rowcount)

        try:
            return int(await self.mysql_db.circuit.call(_do_exec_many))
        except CircuitOpenError as e:
            print(f"MySQL circuit open, fast-fail executemany: {query} | {e}")
            raise

    async def _fetch_one(self, query: str, params: tuple[Any, ...] = ()) -> dict | None:
        async def _do_fetch_one() -> dict | None:
            async with self.mysql_db.cursor() as cur:
                await cur.execute(query, params)
                return await cur.fetchone()

        try:
            return await self.mysql_db.circuit.call(_do_fetch_one)
        except CircuitOpenError as e:
            print(f"MySQL circuit open, fast-fail fetch_one: {query} | {params} | {e}")
            raise

    async def _fetch_all(self, query: str, params: tuple[Any, ...] = ()) -> list[dict]:
        async def _do_fetch_all() -> list[dict]:
            async with self.mysql_db.cursor() as cur:
                await cur.execute(query, params)
                return await cur.fetchall()

        try:
            return await self.mysql_db.circuit.call(_do_fetch_all)
        except CircuitOpenError as e:
            print(f"MySQL circuit open, fast-fail fetch_all: {query} | {params} | {e}")
            raise

    async def find_by_id(self, id_value: Any, columns: Sequence[str] | None = None) -> dict | None:
        pk = self._assert_column_name(self.primary_key)
        col_sql = self._columns_sql(columns)
        query = f"SELECT {col_sql} FROM {self.table_name} WHERE {pk} = %s LIMIT 1"
        return await self._fetch_one(query, (id_value,))

    async def find_one(
        self,
        filters: dict[str, Any] | None = None,
        in_filters: dict[str, Sequence[Any]] | None = None,
        like_filters: dict[str, str] | None = None,
        columns: Sequence[str] | None = None,
        order_by: Sequence[str] | None = None,
    ) -> dict | None:
        col_sql = self._columns_sql(columns)
        where_sql, params = self._build_where(filters, in_filters, like_filters)
        order_sql = self._build_order_by(order_by)
        query = f"SELECT {col_sql} FROM {self.table_name}{where_sql}{order_sql} LIMIT 1"
        return await self._fetch_one(query, params)

    async def find_many(
        self,
        filters: dict[str, Any] | None = None,
        in_filters: dict[str, Sequence[Any]] | None = None,
        like_filters: dict[str, str] | None = None,
        columns: Sequence[str] | None = None,
        order_by: Sequence[str] | None = None,
        limit: int | None = None,
        offset: int | None = None,
    ) -> list[dict]:
        col_sql = self._columns_sql(columns)
        where_sql, params = self._build_where(filters, in_filters, like_filters)
        order_sql = self._build_order_by(order_by)
        page_sql = ""
        page_params: list[Any] = []
        if limit is not None and limit > 0:
            page_sql += " LIMIT %s"
            page_params.append(limit)
            if offset is not None and offset >= 0:
                page_sql += " OFFSET %s"
                page_params.append(offset)
        elif offset is not None and offset > 0:
            page_sql += " LIMIT 18446744073709551615 OFFSET %s"
            page_params.append(offset)

        query = f"SELECT {col_sql} FROM {self.table_name}{where_sql}{order_sql}{page_sql}"
        return await self._fetch_all(query, params + tuple(page_params))

    async def insert_one(self, data: dict[str, Any]) -> Any:
        if not data:
            raise ValueError("insert data cannot be empty")

        columns = [self._assert_column_name(c) for c in data.keys()]
        placeholders = ", ".join(["%s"] * len(columns))
        query = f"INSERT INTO {self.table_name} ({', '.join(columns)}) VALUES ({placeholders})"
        await self._execute(query, tuple(data.values()))

        if self.primary_key in data:
            return data[self.primary_key]

        row = await self._fetch_one("SELECT LAST_INSERT_ID() AS id")
        return row["id"] if row else None

    async def insert_many(self, data_list: list[dict[str, Any]]) -> int:
        if not data_list:
            return 0

        columns = [self._assert_column_name(c) for c in data_list[0].keys()]
        placeholders = ", ".join(["%s"] * len(columns))
        query = f"INSERT INTO {self.table_name} ({', '.join(columns)}) VALUES ({placeholders})"
        params = [tuple(item.get(col) for col in columns) for item in data_list]
        return await self._executemany(query, params)

    async def update_by_id(self, id_value: Any, update_data: dict[str, Any]) -> bool:
        if not update_data:
            return False
        sets = [f"{self._assert_column_name(k)} = %s" for k in update_data.keys()]
        pk = self._assert_column_name(self.primary_key)
        query = f"UPDATE {self.table_name} SET {', '.join(sets)} WHERE {pk} = %s"
        rowcount = await self._execute(query, tuple(update_data.values()) + (id_value,))
        return rowcount > 0

    async def update_where(
        self,
        update_data: dict[str, Any],
        filters: dict[str, Any] | None = None,
        in_filters: dict[str, Sequence[Any]] | None = None,
        like_filters: dict[str, str] | None = None,
    ) -> int:
        if not update_data:
            return 0
        sets = [f"{self._assert_column_name(k)} = %s" for k in update_data.keys()]
        where_sql, where_params = self._build_where(filters, in_filters, like_filters)
        query = f"UPDATE {self.table_name} SET {', '.join(sets)}{where_sql}"
        return await self._execute(query, tuple(update_data.values()) + where_params)

    async def delete_by_id(self, id_value: Any) -> bool:
        pk = self._assert_column_name(self.primary_key)
        query = f"DELETE FROM {self.table_name} WHERE {pk} = %s"
        rowcount = await self._execute(query, (id_value,))
        return rowcount > 0

    async def delete_where(
        self,
        filters: dict[str, Any] | None = None,
        in_filters: dict[str, Sequence[Any]] | None = None,
        like_filters: dict[str, str] | None = None,
    ) -> int:
        where_sql, params = self._build_where(filters, in_filters, like_filters)
        query = f"DELETE FROM {self.table_name}{where_sql}"
        return await self._execute(query, params)

    async def upsert_one(
        self,
        data: dict[str, Any],
        conflict_columns: Sequence[str],
        update_columns: Sequence[str] | None = None,
    ) -> Any:
        if not data:
            raise ValueError("upsert data cannot be empty")
        if not conflict_columns:
            raise ValueError("conflict_columns cannot be empty")

        columns = [self._assert_column_name(c) for c in data.keys()]
        placeholders = ", ".join(["%s"] * len(columns))

        update_cols = list(update_columns) if update_columns else [c for c in data.keys() if c not in set(conflict_columns)]
        if update_cols:
            update_sql = ", ".join(
                f"{self._assert_column_name(c)} = VALUES({self._assert_column_name(c)})"
                for c in update_cols
            )
            query = (
                f"INSERT INTO {self.table_name} ({', '.join(columns)}) VALUES ({placeholders}) "
                f"ON DUPLICATE KEY UPDATE {update_sql}"
            )
        else:
            query = f"INSERT IGNORE INTO {self.table_name} ({', '.join(columns)}) VALUES ({placeholders})"

        await self._execute(query, tuple(data.values()))
        if self.primary_key in data:
            return data[self.primary_key]
        row = await self._fetch_one("SELECT LAST_INSERT_ID() AS id")
        return row["id"] if row else None
