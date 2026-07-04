from __future__ import annotations

from typing import Any

from bms_copilot.src.iface.agent.api_base import (
    IChatProviderAdapter,
    IEmbeddingProviderAdapter,
    ProviderRequestContext,
)
from src.iface.agent.providers import ChatMessage, ChatResult, EmbeddingResult


class DeepSeekChatProvider(IChatProviderAdapter):
    provider_name = "deepseek"

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
        prompt_head = messages[-1].content if messages else ""
        return ChatResult(
            text=f"[deepseek:{model}] {prompt_head[:200]}",
            raw={
                "provider_request": {
                    "messages": messages,
                    "temperature": temperature,
                    "max_tokens": max_tokens,
                    "response_format": response_format,
                    "context": context.to_dict() if context else {},
                }
            },
            usage={
                "input_tokens": sum(
                    len(message.content.split()) for message in messages
                ),
                "output_tokens": 24,
            },
            finish_reason="stop",
            provider=self.provider_name,
            model=model,
        )


class DeepSeekEmbeddingProvider(IEmbeddingProviderAdapter):
    provider_name = "deepseek"

    async def embed(
        self,
        texts: list[str],
        *,
        model: str,
        context: ProviderRequestContext | None = None,
    ) -> EmbeddingResult:
        vectors = [[float(len(text)), 0.5, 0.5] for text in texts]
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
