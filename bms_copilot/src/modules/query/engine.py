from typing import Any

from beanie import Document

from src.repo.mongo_client import MongoDBClient
from src.repo.mysql_client import MySQLClient

# 安全限制
_MAX_LIMIT = 100
_QUERY_TIMEOUT_SEC = 15
_ALLOWED_MONGO_COLLECTIONS = {"monitoring_records", "edge_event_envelopes"}
_ALLOWED_MYSQL_TABLES = {"device_entities", "species_profiles"}


class QueryEngine:
    """查询引擎：解析 LLM 返回的结构化查询并执行。

    支持的 source:
    - ``mongo``：Beanie ODM 查询（只读）
    - ``mysql``：MySQL 查询（只读 SELECT）
    """

    def __init__(
        self,
        mongo_client: MongoDBClient | None = None,
        mysql_client: MySQLClient | None = None,
    ) -> None:
        self._mongo = mongo_client
        self._mysql = mysql_client

    async def execute(self, query_spec: dict[str, Any]) -> dict[str, Any]:
        """执行一条结构化查询，返回结果。"""
        source = (query_spec.get("source") or "").strip().lower()

        if source == "mongo":
            return await self._exec_mongo(query_spec)
        if source == "mysql":
            return await self._exec_mysql(query_spec)
        return {"error": f"unsupported source: {source}"}

    async def _exec_mongo(self, spec: dict[str, Any]) -> dict[str, Any]:
        collection = (spec.get("collection") or "").strip()
        if collection not in _ALLOWED_MONGO_COLLECTIONS:
            return {"error": f"collection '{collection}' is not allowed"}

        mongo = self._mongo
        if mongo is None or not mongo.is_initialized:
            return {"error": "mongo client not available"}

        # 获取 Beanie Document 类
        doc_cls = _resolve_beanie_doc(collection)
        if doc_cls is None:
            return {"error": f"document model for '{collection}' not found"}

        try:
            # 聚合查询优先
            pipeline = spec.get("aggregate")
            if pipeline and isinstance(pipeline, list):
                return await self._run_mongo_aggregate(doc_cls, pipeline)

            # 普通查询
            return await self._run_mongo_find(doc_cls, spec)
        except Exception as exc:
            return {"error": f"mongo query failed: {exc}"}

    async def _run_mongo_find(
        self, doc_cls: type[Document], spec: dict[str, Any]
    ) -> dict[str, Any]:
        filter_dict = spec.get("filter") or {}
        sort_dict = spec.get("sort") or {}
        limit = min(int(spec.get("limit", 20)), _MAX_LIMIT)

        query = doc_cls.find(filter_dict)
        if sort_dict:
            query = query.sort([(k, v) for k, v in sort_dict.items()])
        query = query.limit(limit)

        results = await query.to_list()
        return {
            "source": "mongo",
            "collection": spec.get("collection"),
            "count": len(results),
            "results": [_serialize_doc(r) for r in results],
        }

    async def _run_mongo_aggregate(
        self, doc_cls: type[Document], pipeline: list[dict[str, Any]]
    ) -> dict[str, Any]:
        # 限制返回数量
        safe_pipeline = list(pipeline)
        has_limit = any("$limit" in stage for stage in safe_pipeline)
        if not has_limit:
            safe_pipeline.append({"$limit": _MAX_LIMIT})

        cursor = doc_cls.aggregate(safe_pipeline)
        results = await cursor.to_list()
        return {
            "source": "mongo",
            "collection": doc_cls.__name__,
            "count": len(results),
            "results": [_serialize_aggregate(r) for r in results],
        }

    async def _exec_mysql(self, spec: dict[str, Any]) -> dict[str, Any]:
        table = (spec.get("table") or "").strip()
        if table not in _ALLOWED_MYSQL_TABLES:
            return {"error": f"table '{table}' is not allowed"}

        mysql = self._mysql
        if mysql is None:
            return {"error": "mysql client not available"}

        try:
            return await self._run_mysql_select(mysql, spec)
        except Exception as exc:
            return {"error": f"mysql query failed: {exc}"}

    async def _run_mysql_select(
        self, mysql: MySQLClient, spec: dict[str, Any]
    ) -> dict[str, Any]:
        table = spec["table"]
        filter_dict = spec.get("filter") or {}
        columns = spec.get("columns") or ["*"]
        limit = min(int(spec.get("limit", 20)), _MAX_LIMIT)
        order_by = spec.get("order_by")

        col_clause = ", ".join(columns) if columns != ["*"] else "*"
        where_clauses: list[str] = []
        params: list[Any] = []

        for key, value in filter_dict.items():
            where_clauses.append(f"`{key}` = %s")
            params.append(value)

        sql = f"SELECT {col_clause} FROM `{table}`"
        if where_clauses:
            sql += " WHERE " + " AND ".join(where_clauses)
        if order_by:
            sql += f" ORDER BY {order_by}"
        sql += f" LIMIT {limit}"

        async with mysql.cursor() as cursor:
            await cursor.execute(sql, params)
            rows = await cursor.fetchall()

        return {
            "source": "mysql",
            "table": table,
            "count": len(rows),
            "results": [_serialize_mysql_row(r) for r in rows],
        }


def _resolve_beanie_doc(collection: str) -> type[Document] | None:
    """根据集合名解析对应的 Beanie Document 类。"""
    if collection == "monitoring_records":
        from src.models.business.event import MonitoringRecord

        return MonitoringRecord
    if collection == "edge_event_envelopes":
        from src.models.business.event import EdgeEventEnvelope

        return EdgeEventEnvelope
    return None


def _serialize_doc(doc: Document) -> dict[str, Any]:
    """将 Beanie Document 序列化为可 JSON 序列化的 dict。"""
    data = doc.model_dump()
    # 处理 ObjectId / UUID 等非 JSON 原生类型
    for key, value in data.items():
        if hasattr(value, "hex"):  # ObjectId / UUID
            data[key] = str(value)
    # 兜底：任何单个字符串字段超过 10KB 则截断
    _MAX_STR_LEN = 10 * 1024
    for key, value in data.items():
        if isinstance(value, str) and len(value) > _MAX_STR_LEN:
            data[key] = value[:_MAX_STR_LEN] + "...(truncated)"
    return data


def _serialize_aggregate(raw: Any) -> dict[str, Any]:
    """将聚合管道的输出序列化。"""
    if isinstance(raw, dict):
        return {str(k): str(v) if hasattr(v, "hex") else v for k, v in raw.items()}
    return {"result": str(raw)}


def _serialize_mysql_row(row: Any) -> dict[str, Any]:
    """将 MySQL 行（DictCursor 返回的 dict）序列化。"""
    if isinstance(row, dict):
        result = {}
        for k, v in row.items():
            if isinstance(v, bytes):
                result[str(k)] = v.decode("utf-8", errors="replace")
            else:
                result[str(k)] = v
        return result
    return {"row": str(row)}
