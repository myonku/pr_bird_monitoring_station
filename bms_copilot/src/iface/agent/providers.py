from __future__ import annotations

from typing import Any, Protocol, Sequence

from msgspec import Struct, field


class ChatMessage(Struct, kw_only=True):
    role: str
    content: str
    name: str | None = None
    tool_call_id: str | None = None
    tool_calls: list[dict[str, Any]] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


class ChatResult(Struct, kw_only=True):
    text: str
    raw: Any | None = None
    usage: dict[str, int] = field(default_factory=dict)
    finish_reason: str | None = None
    provider: str | None = None
    model: str | None = None


class EmbeddingResult(Struct, kw_only=True):
    vectors: list[list[float]]
    raw: Any | None = None
    provider: str | None = None
    model: str | None = None


class IChatProvider(Protocol):
    provider_name: str

    async def generate(
        self,
        messages: Sequence[ChatMessage],
        *,
        model: str,
        temperature: float = 0.2,
        max_tokens: int = 1024,
        response_format: dict[str, Any] | None = None,
    ) -> ChatResult: ...


class IEmbeddingProvider(Protocol):
    provider_name: str

    async def embed(
        self,
        texts: Sequence[str],
        *,
        model: str,
    ) -> EmbeddingResult: ...
