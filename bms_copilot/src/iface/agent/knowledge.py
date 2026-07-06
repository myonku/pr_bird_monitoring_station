from __future__ import annotations

from typing import Any, Protocol

from msgspec import Struct, field


class RetrievedChunk(Struct, kw_only=True):
    source_id: str
    title: str
    snippet: str
    score: float
    metadata: dict[str, Any] = field(default_factory=dict)


class IKnowledgeRetriever(Protocol):
    async def retrieve(
        self,
        query: str,
        *,
        top_k: int = 5,
        filters: dict | None = None,
    ) -> list[RetrievedChunk]: ...
