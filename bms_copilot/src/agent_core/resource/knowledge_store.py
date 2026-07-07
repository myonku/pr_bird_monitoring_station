from typing import Any
from pymilvus import CollectionSchema, DataType, FieldSchema, MilvusClient

from src.iface.agent_resource.knowledge_store import IKnowledgeStore
from src.models.agent.knowledge import KnowledgeChunk, RetrievedChunk

_COLLECTION_NAME = "species_knowledge"


class MilvusKnowledgeStore(IKnowledgeStore):
    """基于 Milvus 向量库的知识块存储。

    集合 ``species_knowledge`` 的 schema::

        chunk_id   (VARCHAR, 主键)
        vector     (FLOAT_VECTOR, dim 由 ensure_collection 指定)
        text       (VARCHAR, 块原文)
        title      (VARCHAR, 标题)
        species_id (VARCHAR, 归属物种)
    """

    def __init__(self, milvus: MilvusClient) -> None:
        if milvus is None:
            raise ValueError("milvus client is required")
        self._client = milvus

    async def ensure_collection(self, dimension: int) -> None:
        import asyncio

        def _create() -> None:
            if self._client.has_collection(_COLLECTION_NAME):
                return

            schema = CollectionSchema(
                fields=[
                    FieldSchema(
                        name="chunk_id",
                        dtype=DataType.VARCHAR,
                        max_length=64,
                        is_primary=True,
                    ),
                    FieldSchema(
                        name="vector",
                        dtype=DataType.FLOAT_VECTOR,
                        dim=dimension,
                    ),
                    FieldSchema(
                        name="text",
                        dtype=DataType.VARCHAR,
                        max_length=8192,
                    ),
                    FieldSchema(
                        name="title",
                        dtype=DataType.VARCHAR,
                        max_length=256,
                    ),
                    FieldSchema(
                        name="species_id",
                        dtype=DataType.VARCHAR,
                        max_length=64,
                    ),
                ],
                description="bird species knowledge chunks",
            )
            self._client.create_collection(
                collection_name=_COLLECTION_NAME,
                schema=schema,
            )
            # 创建 IVF_FLAT 索引加速搜索
            index_params: Any = {
                "metric_type": "IP",
                "index_type": "IVF_FLAT",
                "params": {"nlist": 128},
            }
            self._client.create_index(
                collection_name=_COLLECTION_NAME,
                index_params=index_params,
            )
            self._client.load_collection(_COLLECTION_NAME)

        await asyncio.to_thread(_create)

    async def insert_chunks(
        self, chunks: list[KnowledgeChunk], vectors: list[list[float]]
    ) -> int:
        import asyncio

        if not chunks or not vectors:
            return 0
        if len(chunks) != len(vectors):
            raise ValueError(
                f"chunks ({len(chunks)}) and vectors ({len(vectors)}) must have same length"
            )

        def _insert() -> int:
            data: list[dict[str, Any]] = []
            for chunk, vec in zip(chunks, vectors):
                data.append(
                    {
                        "chunk_id": chunk.chunk_id,
                        "vector": vec,
                        "text": chunk.text,
                        "title": chunk.title,
                        "species_id": chunk.species_id,
                    }
                )
            result = self._client.insert(
                collection_name=_COLLECTION_NAME,
                data=data,
            )
            return result.get("insert_count", 0)

        return await asyncio.to_thread(_insert)

    async def search(
        self,
        query_vector: list[float],
        *,
        top_k: int = 5,
    ) -> list[RetrievedChunk]:
        import asyncio

        def _search() -> list[RetrievedChunk]:
            raw = self._client.search(
                collection_name=_COLLECTION_NAME,
                data=[query_vector],
                limit=top_k,
                output_fields=["chunk_id", "text", "title", "species_id"],
                search_params={"metric_type": "IP", "params": {"nprobe": 16}},
            )
            results: list[RetrievedChunk] = []
            for hits in raw:
                for hit in hits:
                    fields = hit.get("entity", {}) or {}
                    chunk_id = str(hit.get("id", fields.get("chunk_id", "")))
                    results.append(
                        RetrievedChunk(
                            source_id=chunk_id,
                            title=str(fields.get("title", "")),
                            snippet=str(fields.get("text", "")),
                            score=float(hit.get("distance", 0.0)),
                            metadata={
                                "species_id": str(fields.get("species_id", "")),
                            },
                        )
                    )
            return results

        return await asyncio.to_thread(_search)

    async def count(self) -> int:
        import asyncio

        def _count() -> int:
            result = self._client.query(
                collection_name=_COLLECTION_NAME,
                filter="",
                output_fields=["count(*)"],
            )
            if result and len(result) > 0:
                return result[0].get("count(*)", 0)
            return 0

        return await asyncio.to_thread(_count)
