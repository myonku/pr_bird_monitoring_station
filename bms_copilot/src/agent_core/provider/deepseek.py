from __future__ import annotations

from src.models.agent.api import ChatRequest, EmbeddingRequest
from src.iface.agent.providers import (
    ChatResult,
    EmbeddingResult,
    IChatProvider,
    IEmbeddingProvider,
)


class DeepSeekChatProvider(IChatProvider):
    provider_name = "deepseek"

    async def generate(self, request: ChatRequest) -> ChatResult:
        prompt_head = request.messages[-1].content if request.messages else ""
        return ChatResult(
            text=f"[deepseek:{request.model}] {prompt_head[:200]}",
            raw={"provider_request": request.to_dict()},
            usage={
                "input_tokens": sum(
                    len(message.content.split()) for message in request.messages
                ),
                "output_tokens": 24,
            },
            finish_reason="stop",
            provider=self.provider_name,
            model=request.model,
        )


class DeepSeekEmbeddingProvider(IEmbeddingProvider):
    provider_name = "deepseek"

    async def embed(self, request: EmbeddingRequest) -> EmbeddingResult:
        vectors = [[float(len(text)), 0.5, 0.5] for text in request.texts]
        return EmbeddingResult(
            vectors=vectors,
            raw={"provider_request": request.to_dict()},
            provider=self.provider_name,
            model=request.model,
        )
