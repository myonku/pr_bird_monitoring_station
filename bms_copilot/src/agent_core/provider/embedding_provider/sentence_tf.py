import asyncio
from src.models.agent.api import EmbeddingRequest, EmbeddingResult
from src.iface.agent.providers import IEmbeddingProvider


class SentenceEmbeddingProvider(IEmbeddingProvider):
    """基于 sentence-transformers 的向量化提供器。

    模型采用延迟加载（lazy loading），避免在启动阶段与 YOLO 等
    其他 PyTorch 模型同时加载导致 OpenBLAS 内存分配失败。
    """

    provider_name = "sentence_transformers"

    # BAAI/bge-small-zh-v1.5 固定输出 512 维向量
    default_dimension: int = 512

    def __init__(self, model_name: str = "BAAI/bge-small-zh-v1.5"):
        self._model_name = model_name
        self._model = None
        self._dimension: int = 512

    @property
    def dimension(self) -> int:
        """向量维度。若模型尚未加载则返回已知常量 512。"""
        return self._dimension if self._model is not None else self.default_dimension

    def _lazy_load(self) -> None:
        if self._model is not None:
            return
        from sentence_transformers import SentenceTransformer

        self._model = SentenceTransformer(self._model_name)
        dimension = self._model.get_embedding_dimension()
        self._dimension = dimension if dimension is not None else self.default_dimension

    async def embed(self, request: EmbeddingRequest) -> EmbeddingResult:
        if self._model is None:
            await asyncio.to_thread(self._lazy_load)
        if self._model is None:
            raise RuntimeError("SentenceEmbeddingProvider 模型加载失败")
        vectors = await asyncio.to_thread(
            self._model.encode, request.texts, normalize_embeddings=True
        )
        return EmbeddingResult(
            vectors=vectors.tolist(),
            provider=self.provider_name,
            model=request.model or "unknown",
        )
