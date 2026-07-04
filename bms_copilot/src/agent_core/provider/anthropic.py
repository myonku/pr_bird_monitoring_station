from __future__ import annotations

from typing import Any

from bms_copilot.src.iface.agent.api_base import (
    IChatProviderAdapter,
    IEmbeddingProviderAdapter,
    ProviderRequestContext,
)
from src.iface.agent.providers import ChatMessage, ChatResult, EmbeddingResult


class AnthropicChatProvider(IChatProviderAdapter):
    provider_name = "anthropic"

    async def generate(
        self,
        messages: list[ChatMessage],
        *,
        model: str,
        temperature: float = 0.2,
        max_tokens: int = 1024,
        response_format: dict[str, Any] | None = None,
        context: ProviderRequestContext | None = None,
    ) -> ChatResult:
        summary = " | ".join(message.role for message in messages)
        return ChatResult(
            text=f"[anthropic:{model}] roles={summary}",
            raw={
                "provider_request": {
                    "messages": messages,
                    "temperature": temperature,
                    "max_tokens": max_tokens,
                    "response_format": response_format,
                    "context": context.to_dict() if context else {},
                }
            },
            usage={"input_tokens": len(messages), "output_tokens": 18},
            finish_reason="stop",
            provider=self.provider_name,
            model=model,
        )


class AnthropicEmbeddingProvider(IEmbeddingProviderAdapter):
    provider_name = "anthropic"

    async def embed(
        self,
        texts: list[str],
        *,
        model: str,
        context: ProviderRequestContext | None = None,
    ) -> EmbeddingResult:
        vectors = [[1.0, float(len(text)), 0.0] for text in texts]
        return EmbeddingResult(
            vectors=vectors,
            raw={
                "provider_request": {
                    "texts": texts,
                    "context": context.to_dict() if context else {},
                }
            },
            provider=self.provider_name,
            model=model,
        )
