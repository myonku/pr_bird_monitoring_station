from __future__ import annotations

from time import time

from src.models.auth.ratelimit import RateLimitDecision, RateLimitDescriptor


class RateLimiterService:
    """限流决策服务骨架（普通服务可复用同一接口语义）。"""

    def __init__(self, limit: int = 200, window_sec: int = 60):
        self.limit = max(limit, 1)
        self.window_sec = max(window_sec, 1)
        self._counter: dict[str, tuple[int, float]] = {}

    async def decide(self, descriptor: RateLimitDescriptor) -> RateLimitDecision:
        now = time()
        key = f"{descriptor.transport}:{descriptor.route}:{descriptor.method}:{descriptor.principal_id or descriptor.source_ip}"
        hits, reset_at = self._counter.get(key, (0, now + self.window_sec))
        if now >= reset_at:
            hits = 0
            reset_at = now + self.window_sec

        hits += 1
        self._counter[key] = (hits, reset_at)
        remaining = max(self.limit - hits, 0)
        if hits <= self.limit:
            return RateLimitDecision(
                allowed=True,
                violated_rule_id="",
                retry_after_sec=0,
                remaining=remaining,
                subject_key=key,
                reason="",
            )
        return RateLimitDecision(
            allowed=False,
            violated_rule_id="default-fixed-window",
            retry_after_sec=max(int(reset_at - now), 1),
            remaining=0,
            subject_key=key,
            reason="rate limited",
        )


class DescriptorFactory:
    """协议上下文到 RateLimitDescriptor 的转换骨架。"""

    def build(self, transport: str, route: str, method: str, headers: dict[str, str]) -> RateLimitDescriptor:
        return RateLimitDescriptor(
            scope="internal_grpc",
            transport=transport,
            module=headers.get("x-module", "api_service"),
            action=headers.get("x-action", method),
            route=route,
            method=method,
            authenticated=bool(headers.get("authorization") or headers.get("x-downstream-principal")),
            source_ip=headers.get("x-forwarded-for", ""),
            gateway_id=headers.get("x-gateway-id", ""),
            client_id=headers.get("x-client-id", ""),
            source_service=headers.get("x-source-service", ""),
            target_service=headers.get("x-target-service", "api_service"),
            entity_type="service",
            entity_id=headers.get("x-entity-id", "api_service"),
            principal_id=headers.get("x-downstream-principal", ""),
            session_id=headers.get("x-downstream-session", ""),
            token_id=headers.get("x-downstream-token", ""),
            token_type=headers.get("x-token-type", ""),
            scopes=[v for v in headers.get("x-scopes", "").split(",") if v],
            tags={},
        )


class EnforceInboundUsecase:
    """入站限流编排：Build -> Decide。"""

    def __init__(self, factory: DescriptorFactory, limiter: RateLimiterService):
        self.factory = factory
        self.limiter = limiter

    async def execute(self, transport: str, route: str, method: str, headers: dict[str, str]) -> RateLimitDecision:
        descriptor = self.factory.build(transport, route, method, headers)
        return await self.limiter.decide(descriptor)
