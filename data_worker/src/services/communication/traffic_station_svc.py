from __future__ import annotations

from src.iface.communication.routing_contract import FlowCategory
from src.iface.communication.routing_payload_pipeline import (
    BuildOutboundPayloadRequest,
    IRoutingPayloadPipeline,
)
from src.iface.communication.traffic_station import (
    InboundTrafficRequest,
    ITrafficStation,
    OutboundTrafficRequest,
    TrafficDecision,
    TrafficDispatchResult,
)


class TrafficStationService(ITrafficStation):
    """data_worker 统一流量站点（L2）。"""

    def __init__(self, *, routing_pipeline: IRoutingPayloadPipeline | None) -> None:
        self._routing_pipeline = routing_pipeline

    async def handle_inbound(self, req: InboundTrafficRequest) -> TrafficDecision:
        if req is None or req.flow is None:
            raise ValueError("inbound traffic request is invalid")
        if self._routing_pipeline is None:
            raise RuntimeError("traffic station dependencies are required")

        profile = await self._routing_pipeline.resolve_route_profile(req.flow)
        accepted = True
        reason = "accepted"

        if _requires_target_endpoint(profile.flow_category):
            if not (profile.target_service_name or "").strip():
                accepted = False
                reason = "route_target_unresolved"
            elif not (profile.target_endpoint or "").strip():
                accepted = False
                reason = "route_endpoint_unresolved"

        metadata = {
            "flow_category": profile.flow_category,
            "security_policy": profile.security_policy,
            "target_service": profile.target_service_name,
            "target_endpoint": profile.target_endpoint,
        }
        return TrafficDecision(
            accepted=accepted,
            reason=reason,
            profile=profile,
            metadata=metadata,
        )

    async def send_outbound(self, req: OutboundTrafficRequest) -> TrafficDispatchResult:
        if req is None or req.flow is None:
            raise ValueError("outbound traffic request is invalid")
        if self._routing_pipeline is None:
            raise RuntimeError("traffic station dependencies are required")

        plan = await self._routing_pipeline.build_outbound_payload(
            BuildOutboundPayloadRequest(
                flow=req.flow,
                plain_payload=req.payload,
                additional_data=dict(req.headers or {}),
            )
        )

        target_endpoint = (plan.route_profile.target_endpoint or "").strip()
        if not target_endpoint and plan.target is not None:
            target_endpoint = (plan.target.endpoint or "").strip()

        return TrafficDispatchResult(
            profile=plan.route_profile,
            target_endpoint=target_endpoint,
            payload=plan.plain_payload,
            metadata={
                "flow_category": plan.route_profile.flow_category,
                "security_policy": plan.route_profile.security_policy,
                "target_service": plan.route_profile.target_service_name,
                "target_endpoint": target_endpoint,
            },
        )


def _requires_target_endpoint(category: FlowCategory) -> bool:
    return category in {
        "bootstrap_call",
        "remote_auth_verify",
        "external_auth_forward",
        "module_token_refresh",
    }
