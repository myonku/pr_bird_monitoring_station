from __future__ import annotations

from typing import Any, Dict, List, Protocol, Sequence


class ChatMessage(dict):
    """
    统一消息格式建议：
    {"role": "system|user|assistant|tool", "content": "...", "name": "...(optional)"}
    """

    pass


class ChatResult(dict):
    """
    统一返回建议：
    {
      "text": str,
      "raw": Any,
      "usage": {"input_tokens": int, "output_tokens": int}
    }
    """

    pass


class EmbeddingResult(dict):
    """
    统一返回建议：
    {
      "vectors": List[List[float]],
      "raw": Any
    }
    """

    pass


class IChatProvider(Protocol):
    provider_name: str

    async def generate(
        self,
        messages: Sequence[ChatMessage],
        *,
        model: str,
        temperature: float = 0.2,
        max_tokens: int = 1024,
        response_format: Dict[str, Any] | None = None,
    ) -> ChatResult: ...


class IEmbeddingProvider(Protocol):
    provider_name: str

    async def embed(
        self,
        texts: Sequence[str],
        *,
        model: str,
    ) -> EmbeddingResult: ...
