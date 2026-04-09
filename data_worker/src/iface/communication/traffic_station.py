from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from src.iface.communication.routing_contract import FlowRouteInput, RouteProfile


@dataclass(slots=True, kw_only=True)
class InboundTrafficRequest:
    flow: FlowRouteInput
    headers: dict[str, str] = field(default_factory=dict)
    payload: str = ""


@dataclass(slots=True, kw_only=True)
class OutboundTrafficRequest:
    flow: FlowRouteInput
    headers: dict[str, str] = field(default_factory=dict)
    payload: str = ""


@dataclass(slots=True, kw_only=True)
class TrafficDecision:
    accepted: bool
    reason: str = ""
    profile: RouteProfile | None = None
    metadata: dict[str, str] = field(default_factory=dict)


@dataclass(slots=True, kw_only=True)
class TrafficDispatchResult:
    profile: RouteProfile | None = None
    target_endpoint: str = ""
    payload: str = ""
    metadata: dict[str, str] = field(default_factory=dict)


class ITrafficStation(ABC):
    """data_worker 的统一流量站点。

    下游接口调用：
      - communication.IRoutingPayloadPipeline.resolve_route_profile / build_outbound_payload
      - authcontrol.IAuthControl.enforce_inbound / prepare_outbound
      - orchestration.IWorkerOrchestrator.handle_task / handle_inbound_rpc
    """

    @abstractmethod
    async def handle_inbound(self, req: InboundTrafficRequest) -> TrafficDecision:
        raise NotImplementedError

    @abstractmethod
    async def send_outbound(self, req: OutboundTrafficRequest) -> TrafficDispatchResult:
        raise NotImplementedError
