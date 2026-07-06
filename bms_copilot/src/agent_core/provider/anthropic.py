from src.models.agent.api import ChatRequest, EmbeddingRequest, EmbeddingResult
from src.iface.agent.providers import IChatProvider, IEmbeddingProvider

from src.models.agent.api import ChatRequest, ChatResult

class AnthropicChatProvider(IChatProvider):
    provider_name = "anthropic"

    async def generate(self, request: ChatRequest) -> ChatResult:
        summary = " | ".join(message.role for message in request.messages)
        return ChatResult(
            text=f"[anthropic:{request.model}] roles={summary}",
            raw={"provider_request": request.to_dict()},
            usage={"input_tokens": len(request.messages), "output_tokens": 18},
            finish_reason="stop",
            provider=self.provider_name,
            model=request.model,
        )


class AnthropicEmbeddingProvider(IEmbeddingProvider):
    provider_name = "anthropic"

    async def embed(self, request: EmbeddingRequest) -> EmbeddingResult:
        vectors = [[1.0, float(len(text)), 0.0] for text in request.texts]
        return EmbeddingResult(
            vectors=vectors,
            raw={"provider_request": request.to_dict()},
            provider=self.provider_name,
            model=request.model,
        )
