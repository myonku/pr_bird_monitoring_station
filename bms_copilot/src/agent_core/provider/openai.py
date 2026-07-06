from src.models.agent.api import ChatRequest, EmbeddingRequest, EmbeddingResult
from src.iface.agent.providers import IChatProvider, IEmbeddingProvider

from src.models.agent.api import ChatRequest, ChatResult

class OpenAIChatProvider(IChatProvider):
    provider_name = "openai"

    async def generate(self, request: ChatRequest) -> ChatResult:
        combined_text = "\n".join(message.content for message in request.messages)
        return ChatResult(
            text=f"[openai:{request.model}] {combined_text[:200]}",
            raw={"provider_request": request.to_dict()},
            usage={"input_tokens": len(combined_text.split()), "output_tokens": 32},
            finish_reason="stop",
            provider=self.provider_name,
            model=request.model,
        )


class OpenAIEmbeddingProvider(IEmbeddingProvider):
    provider_name = "openai"

    async def embed(self, request: EmbeddingRequest) -> EmbeddingResult:
        vectors = [[float(len(text)), 1.0, 0.0] for text in request.texts]
        return EmbeddingResult(
            vectors=vectors,
            raw={"provider_request": request.to_dict()},
            provider=self.provider_name,
            model=request.model,
        )
