"""基于向量检索的知识块检索器实现。"""

from __future__ import annotations

from src.iface.agent.knowledge import IKnowledgeRetriever
from src.iface.agent.providers import IEmbeddingProvider
from src.iface.agent_resource.knowledge_store import IKnowledgeStore
from src.models.agent.api import EmbeddingRequest
from src.models.agent.knowledge import RetrievedChunk


class MilvusKnowledgeRetriever(IKnowledgeRetriever):
    """基于 Milvus 的知识块检索器。

    流程::

        query text → embedder → query vector → Milvus search → RetrievedChunk[]
    """

    def __init__(
        self,
        embedder: IEmbeddingProvider,
        knowledge_store: IKnowledgeStore,
    ) -> None:
        if embedder is None:
            raise ValueError("embedder is required")
        if knowledge_store is None:
            raise ValueError("knowledge_store is required")
        self._embedder = embedder
        self._store = knowledge_store

    async def retrieve(
        self,
        query: str,
        *,
        top_k: int = 5,
        filters: dict | None = None,
    ) -> list[RetrievedChunk]:
        embed_result = await self._embedder.embed(
            EmbeddingRequest(texts=[query])
        )
        if not embed_result or not embed_result.vectors:
            return []
        query_vector = embed_result.vectors[0]

        results = await self._store.search(
            query_vector=query_vector,
            top_k=top_k,
        )

        results.sort(key=lambda r: r.score, reverse=True)
        return results
