from abc import ABC, abstractmethod

from src.models.agent.knowledge import KnowledgeChunk, RetrievedChunk


class IKnowledgeStore(ABC):
    """知识库存储接口：基于向量库的知识块管理。"""

    @abstractmethod
    async def ensure_collection(self, dimension: int) -> None:
        """确保向量集合已创建，dimension 为 embedding 维度（如 384）。"""
        ...

    @abstractmethod
    async def insert_chunks(
        self, chunks: list[KnowledgeChunk], vectors: list[list[float]]
    ) -> int:
        """批量插入分块及其向量，返回插入数量。"""
        ...

    @abstractmethod
    async def search(
        self,
        query_vector: list[float],
        *,
        top_k: int = 5,
    ) -> list[RetrievedChunk]:
        """向量相似度搜索，返回最相似的 top_k 个块。"""
        ...

    @abstractmethod
    async def count(self) -> int:
        """返回集合中的知识块总数。"""
        ...
