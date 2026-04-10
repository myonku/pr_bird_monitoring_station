from __future__ import annotations

from src.iface.communication.traffic_station import (
    ITrafficStation,
    InboundTrafficRequest,
    OutboundTrafficRequest,
)
from src.iface.orchestration.worker_orchestrator import (
    IWorkerOrchestrator,
    WorkerRequest,
    WorkerResult,
)


class WorkerOrchestratorService(IWorkerOrchestrator):
    """data_worker 顶层编排最小实现。"""

    def __init__(self, *, traffic_station: ITrafficStation | None) -> None:
        self._traffic_station = traffic_station

    async def handle_task(self, req: WorkerRequest) -> WorkerResult:
        if req is None:
            raise ValueError("worker request is required")
        return await self._handle_request(req)

    async def handle_inbound_rpc(self, req: WorkerRequest) -> WorkerResult:
        if req is None:
            raise ValueError("worker request is required")
        return await self._handle_request(req)

    async def _handle_request(self, req: WorkerRequest) -> WorkerResult:
        if self._traffic_station is None:
            raise RuntimeError("worker orchestrator dependencies are required")

        inbound_decision = await self._traffic_station.handle_inbound(
            InboundTrafficRequest(
                flow=req.flow,
                headers=dict(req.inbound_headers or {}),
                payload=req.payload,
            )
        )
        if not inbound_decision.accepted:
            reason = (inbound_decision.reason or "").strip() or "inbound_rejected"
            raise RuntimeError(f"worker inbound denied: {reason}")

        dispatch = await self._traffic_station.send_outbound(
            OutboundTrafficRequest(
                flow=req.flow,
                headers=dict(req.inbound_headers or {}),
                payload=req.payload,
            )
        )
        if dispatch.profile is None:
            raise RuntimeError("worker dispatch profile is required")

        return WorkerResult(
            route_profile=dispatch.profile,
            target_endpoint=dispatch.target_endpoint,
            outbound_headers={
                "x-flow-category": dispatch.profile.flow_category,
            },
            outbound_payload=dispatch.payload,
        )
