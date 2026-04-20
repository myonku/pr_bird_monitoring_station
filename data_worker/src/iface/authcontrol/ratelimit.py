from dataclasses import dataclass, field

from src.models.auth.auth import IdentityContext
from src.models.auth.ratelimit import RateLimitScope


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
