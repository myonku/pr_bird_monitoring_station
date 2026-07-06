from abc import ABC, abstractmethod

from src.models.agent.knowledge import RetrievedChunk


class IKnowledgeRetriever(ABC):
    @abstractmethod
    async def retrieve(
        self,
        query: str,
        *,
        top_k: int = 5,
        filters: dict | None = None,
    ) -> list[RetrievedChunk]: ...
