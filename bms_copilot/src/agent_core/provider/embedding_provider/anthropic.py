from src.models.agent.api import EmbeddingRequest, EmbeddingResult
from src.iface.agent.providers import IEmbeddingProvider


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
