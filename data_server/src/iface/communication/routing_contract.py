from dataclasses import dataclass, field
from typing import Literal


FlowCategory = Literal[
    "bootstrap_call",
    "remote_auth_verify",
    "external_auth_forward",
    "business_forward",
]

SecurityPolicy = Literal["required", "optional", "disabled"]
TargetServiceType = Literal["auth_authority", "internal_service", "unknown"]


@dataclass(slots=True, kw_only=True)
class FlowRouteInput:
    route_key: str = ""

    transport: str = ""
    method: str = ""
    path: str = ""

    source_service: str = ""
    target_service_hint: str = ""

    metadata: dict[str, str] = field(default_factory=dict)


@dataclass(slots=True, kw_only=True)
class RouteProfile:
    target_service_type: TargetServiceType = "unknown"
    target_service_name: str = ""
    target_endpoint: str = ""

    flow_category: FlowCategory = "business_forward"
    security_policy: SecurityPolicy = "required"
