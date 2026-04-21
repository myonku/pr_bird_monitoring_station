from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import cast

from src.models.auth.auth import IdentityContext
from src.models.auth.ratelimit import RateLimitScope
from src.models.auth.auth import TokenType
from src.models.auth.ratelimit import RateLimitDecision, RateLimitDescriptor
from src.models.common.entry_type import EntityType


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


def Build(input_data: InboundRateLimitInput | None) -> RateLimitDescriptor:
    if input_data is None:
        raise ValueError("inbound rate limit input is nil")

    descriptor = RateLimitDescriptor(
        scope=input_data.scope,
        transport=input_data.transport,
        module=input_data.module,
        action=input_data.action,
        route=input_data.route,
        method=input_data.method,
        authenticated=False,
        source_ip=input_data.source_ip,
        gateway_id=input_data.gateway_id,
        client_id=input_data.client_id,
        source_service=input_data.source_service,
        target_service=input_data.target_service,
        entity_type="unknown",
        entity_id="",
        principal_id="",
        session_id="",
        token_id="",
        token_type=cast(TokenType, ""),
        scopes=[],
        tags=dict(input_data.tags or {}),
    )

    identity = input_data.identity
    if identity is not None:
        descriptor.authenticated = True
        descriptor.entity_type = identity.entity_type
        descriptor.entity_id = identity.entity_id
        descriptor.principal_id = identity.principal_id
        descriptor.session_id = str(identity.session_id)
        descriptor.token_id = str(identity.token_id)
        descriptor.token_type = identity.token_type
        descriptor.scopes = list(identity.scopes)

    return descriptor


@dataclass(slots=True, kw_only=True)
class InboundControlRequest:
    rate_limit_input: InboundRateLimitInput | None = None


@dataclass(slots=True, kw_only=True)
class InboundControlResult:
    rate_limit_decision: RateLimitDecision | None = None


class IInboundAuthControl(ABC):
    """data_worker 的本地入站认证控制。"""

    @abstractmethod
    async def enforce_inbound(self, req: InboundControlRequest) -> InboundControlResult:
        raise NotImplementedError
