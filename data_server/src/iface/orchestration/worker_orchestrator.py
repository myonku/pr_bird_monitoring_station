from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from src.iface.communication.routing_contract import FlowRouteInput, RouteProfile


@dataclass(slots=True, kw_only=True)
class WorkerRequest:
    flow: FlowRouteInput
    inbound_headers: dict[str, str] = field(default_factory=dict)
    payload: str = ""

    affinity_key: str = ""
    require_tags: list[str] = field(default_factory=list)

    runtime_mode: str = ""
    request_trace: dict[str, str] = field(default_factory=dict)


@dataclass(slots=True, kw_only=True)
class WorkerResult:
    route_profile: RouteProfile | None = None
    target_endpoint: str = ""

    outbound_headers: dict[str, str] = field(default_factory=dict)
    outbound_payload: str = ""


class IWorkerOrchestrator(ABC):
    """data_server 顶层编排契约。

    下游接口调用：
      - communication.ITrafficStation.handle_inbound / send_outbound
      - communication.IRoutingPayloadPipeline.resolve_route_profile / build_outbound_payload
      - authcontrol.IInboundAuthControl.enforce_inbound
      - common.ILocalCredentialManager.load_active_credential
    """

    @abstractmethod
    async def handle_task(self, req: WorkerRequest) -> WorkerResult:
        raise NotImplementedError

    @abstractmethod
    async def handle_inbound_rpc(self, req: WorkerRequest) -> WorkerResult:
        raise NotImplementedError
