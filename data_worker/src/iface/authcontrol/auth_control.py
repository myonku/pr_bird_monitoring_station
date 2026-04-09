from abc import ABC, abstractmethod
from dataclasses import dataclass

from src.iface.authcontrol.ratelimit import InboundRateLimitInput
from src.models.auth.auth import IdentityContext
from src.models.auth.ratelimit import RateLimitDecision


@dataclass(slots=True, kw_only=True)
class InboundAuthControlRequest:
    identity: IdentityContext | None = None
    rate_limit_input: InboundRateLimitInput | None = None


@dataclass(slots=True, kw_only=True)
class InboundAuthControlResult:
    identity: IdentityContext | None = None
    rate_limit_decision: RateLimitDecision | None = None


@dataclass(slots=True, kw_only=True)
class OutboundAuthControlRequest:
    identity: IdentityContext | None = None
    target_service: str = ""
    rate_limit_input: InboundRateLimitInput | None = None


@dataclass(slots=True, kw_only=True)
class OutboundAuthControlResult:
    rate_limit_decision: RateLimitDecision | None = None


class IAuthControl(ABC):
    """data_worker 的认证与限流控制点。

    下游接口调用：
      - authcontrol.IDescriptorFactory.build
      - authcontrol.IRateLimiter.decide
    """

    @abstractmethod
    async def enforce_inbound(self, req: InboundAuthControlRequest) -> InboundAuthControlResult:
        raise NotImplementedError

    @abstractmethod
    async def prepare_outbound(self, req: OutboundAuthControlRequest) -> OutboundAuthControlResult:
        raise NotImplementedError
