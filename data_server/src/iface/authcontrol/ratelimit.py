from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from src.models.auth.auth import IdentityContext
from src.models.auth.ratelimit import RateLimitDecision, RateLimitDescriptor, RateLimitScope


@dataclass(slots=True, kw_only=True)
class InboundRateLimitInput:
    scope: RateLimitScope
    transport: str

    module: str
    action: str
    route: str
    method: str

    source_ip: str = ""
    gateway_id: str = ""
    client_id: str = ""

    source_service: str = ""
    target_service: str = ""

    headers: dict[str, str] = field(default_factory=dict)
    tags: dict[str, str] = field(default_factory=dict)

    identity: IdentityContext | None = None


class IDescriptorFactory(ABC):
    """根据入站输入构建与协议无关的限流描述符。"""

    @abstractmethod
    async def build(self, input_data: InboundRateLimitInput) -> RateLimitDescriptor:
        raise NotImplementedError


class IRateLimiter(ABC):
    """auth-control 使用的限流决策端口。"""

    @abstractmethod
    async def decide(self, descriptor: RateLimitDescriptor) -> RateLimitDecision:
        raise NotImplementedError
