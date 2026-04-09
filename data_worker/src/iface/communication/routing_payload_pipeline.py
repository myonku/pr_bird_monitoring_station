from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from src.iface.communication.commsec_contract import ChannelEncryptResult, SecureChannelEnsureRequest
from src.iface.communication.routing_contract import FlowCategory, FlowRouteInput, RouteProfile
from src.models.common.instance import ServiceInstance
from src.models.commsec.commsec import SecureChannelSession


@dataclass(slots=True, kw_only=True)
class BuildOutboundPayloadRequest:
    flow: FlowRouteInput
    plain_payload: str
    additional_data: dict[str, str] = field(default_factory=dict)
    ensure_channel: SecureChannelEnsureRequest | None = None
    preferred_target: ServiceInstance | None = None


@dataclass(slots=True, kw_only=True)
class OutboundPayloadPlan:
    route_profile: RouteProfile
    target: ServiceInstance | None = None

    plain_payload: str = ""
    encrypted: ChannelEncryptResult | None = None
    channel: SecureChannelSession | None = None


class IRoutingPayloadPipeline(ABC):
    """路由分类与出站载荷规划。

    下游接口调用：
      - common.IRegistryManager.choose_endpoint
      - communication.ICommsecChannelManager.ensure_channel / encrypt_payload
            - common.IKeyManager.lookup_public_key（可选策略路径）
    """

    @abstractmethod
    async def resolve_route_profile(self, flow: FlowRouteInput) -> RouteProfile:
        raise NotImplementedError

    @abstractmethod
    async def classify_flow(self, flow: FlowRouteInput) -> FlowCategory:
        raise NotImplementedError

    @abstractmethod
    async def build_outbound_payload(self, req: BuildOutboundPayloadRequest) -> OutboundPayloadPlan:
        raise NotImplementedError
