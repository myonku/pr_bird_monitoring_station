from __future__ import annotations

from src.models.auth.ratelimit import RateLimitDecision, RateLimitDescriptor


class RateLimiterService:
    """限流决策服务骨架（普通服务可复用同一接口语义）。"""

    async def decide(self, descriptor: RateLimitDescriptor) -> RateLimitDecision:
        ...


class DescriptorFactory:
    """协议上下文到 RateLimitDescriptor 的转换骨架。"""

    def build(self, transport: str, route: str, method: str, headers: dict[str, str]) -> RateLimitDescriptor:
        ...


class EnforceInboundUsecase:
    """入站限流编排：Build -> Decide。"""

    def __init__(self, factory: DescriptorFactory, limiter: RateLimiterService):
        self.factory = factory
        self.limiter = limiter

    async def execute(self, transport: str, route: str, method: str, headers: dict[str, str]) -> RateLimitDecision:
        ...
