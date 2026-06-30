from __future__ import annotations

from typing import Protocol, TypedDict


class RetrievedChunk(TypedDict):
    source_id: str
    title: str
    snippet: str
    score: float
    metadata: dict


class IKnowledgeRetriever(Protocol):
    async def retrieve(
        self,
        query: str,
        *,
        top_k: int = 5,
        filters: dict | None = None,
    ) -> list[RetrievedChunk]: ...
