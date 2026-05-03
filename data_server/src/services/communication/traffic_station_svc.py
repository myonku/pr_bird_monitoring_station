from __future__ import annotations

from src.iface.authcontrol.auth_control import (
    IInboundAuthControl,
    InboundControlRequest,
    InboundRateLimitInput,
)
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
    """data_server 统一流量站点（L2）。"""

    def __init__(
        self,
        *,
        routing_pipeline: IRoutingPayloadPipeline | None,
        auth_control: IInboundAuthControl | None = None,
    ) -> None:
        self._routing_pipeline = routing_pipeline
        self._auth_control = auth_control

    async def handle_inbound(self, req: InboundTrafficRequest) -> TrafficDecision:
        if req is None or req.flow is None:
            raise ValueError("inbound traffic request is invalid")
        if self._routing_pipeline is None:
            raise RuntimeError("traffic station dependencies are required")

        profile = await self._routing_pipeline.resolve_route_profile(req.flow)
        accepted = True
        reason = "accepted"

        if self._auth_control is not None:
            flow = req.flow
            control_result = await self._auth_control.enforce_inbound(
                InboundControlRequest(
                    rate_limit_input=InboundRateLimitInput(
                        scope="auth",
                        transport=flow.transport or "grpc",
                        module=flow.source_service or "",
                        action=flow.route_key or "",
                        route=flow.path or "",
                        method=flow.method or "",
                        source_ip=req.headers.get("x-forwarded-for", ""),
                        source_service=flow.source_service or "",
                        target_service=profile.target_service_name if profile is not None else "",
                        headers=dict(req.headers or {}),
                    )
                )
            )
            if control_result is not None and control_result.rate_limit_decision is not None:
                if not control_result.rate_limit_decision.allowed:
                    return TrafficDecision(
                        accepted=False,
                        reason="rate_limited",
                        profile=profile,
                        metadata={"rate_limit_reason": control_result.rate_limit_decision.reason or ""},
                    )

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
