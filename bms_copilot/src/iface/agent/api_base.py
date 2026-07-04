from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from src.iface.agent.providers import ChatMessage, ChatResult, EmbeddingResult


class ProviderRequestContext:
    """统一的 provider 请求上下文样例。"""

    ...

    def to_dict(self) -> dict[str, Any]:
        """将上下文转换为字典形式。"""
        return {}


class ProviderResponseContext:
    """统一的 provider 响应上下文样例。"""

    ...

    def to_dict(self) -> dict[str, Any]:
        """将上下文转换为字典形式。"""
        return {}


class IProvider(ABC):
    """provider 统一适配基类样例。"""

    provider_name: str


class IChatProviderAdapter(IProvider):
    @abstractmethod
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
        raise NotImplementedError


class IEmbeddingProviderAdapter(IProvider):
    @abstractmethod
    async def embed(
        self,
        texts: list[str],
        *,
        model: str,
        context: ProviderRequestContext | None = None,
    ) -> EmbeddingResult:
        raise NotImplementedError
