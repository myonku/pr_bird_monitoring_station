import asyncio
from src.models.agent.api import EmbeddingRequest, EmbeddingResult
from src.iface.agent.providers import IEmbeddingProvider


class SentenceEmbeddingProvider(IEmbeddingProvider):
    """基于 sentence-transformers 的向量化提供器，使用 MiniLM 模型进行文本嵌入。"""

    provider_name = "sentence_transformers"

    def __init__(self, model_name: str = "BAAI/bge-small-zh-v1.5"):
        from sentence_transformers import SentenceTransformer

        self._model = SentenceTransformer(model_name)
        self._dimension = self._model.get_embedding_dimension()

    async def embed(self, request: EmbeddingRequest) -> EmbeddingResult:
        vectors = await asyncio.to_thread(
            self._model.encode, request.texts, normalize_embeddings=True
        )
        return EmbeddingResult(
            vectors=vectors.tolist(),
            provider=self.provider_name,
            model=request.model or "unknown",
        )
