from abc import ABC, abstractmethod
from src.models.agent.api import (
    ChatRequest,
    ChatResult,
    EmbeddingRequest,
    EmbeddingResult,
)

class IChatProvider(ABC):
    provider_name: str

    @abstractmethod
    async def generate(self, request: ChatRequest) -> ChatResult: ...


class IEmbeddingProvider(ABC):
    provider_name: str

    @abstractmethod
    async def embed(self, request: EmbeddingRequest) -> EmbeddingResult: ...
