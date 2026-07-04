from __future__ import annotations

from typing import Any

from bms_copilot.src.iface.agent.api_base import (
    IChatProviderAdapter,
    IEmbeddingProviderAdapter,
    ProviderRequestContext,
)
from src.iface.agent.providers import ChatMessage, ChatResult, EmbeddingResult


class OpenAIChatProvider(IChatProviderAdapter):
    provider_name = "openai"

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
        combined_text = "\n".join(message.content for message in messages)
        return ChatResult(
            text=f"[openai:{model}] {combined_text[:200]}",
            raw={
                "provider_request": {
                    "messages": messages,
                    "temperature": temperature,
                    "max_tokens": max_tokens,
                    "response_format": response_format,
                    "context": context.to_dict() if context else {},
                }
            },
            usage={"input_tokens": len(combined_text.split()), "output_tokens": 32},
            finish_reason="stop",
            provider=self.provider_name,
            model=model,
        )


class OpenAIEmbeddingProvider(IEmbeddingProviderAdapter):
    provider_name = "openai"

    async def embed(
        self,
        texts: list[str],
        *,
        model: str,
        context: ProviderRequestContext | None = None,
    ) -> EmbeddingResult:
        vectors = [[float(len(text)), 1.0, 0.0] for text in texts]
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
