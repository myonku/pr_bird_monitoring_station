from __future__ import annotations

from src.iface.common.registry_manager import IRegistryManager
from src.iface.communication.routing_contract import (
    FlowCategory,
    FlowRouteInput,
    RouteProfile,
    SecurityPolicy,
    TargetServiceType,
)
from src.iface.communication.routing_payload_pipeline import (
    BuildOutboundPayloadRequest,
    IRoutingPayloadPipeline,
    OutboundPayloadPlan,
)
from src.models.common.instance import ServiceInstance


DEFAULT_AUTH_AUTHORITY_SERVICE = "certification_server"


BOOTSTRAP_CHALLENGE_ROUTE_KEY = "auth.bootstrap.challenge"
BOOTSTRAP_AUTH_ROUTE_KEY = "auth.bootstrap.authenticate"
REMOTE_AUTH_VERIFY_ROUTE_KEY = "auth.remote.verify.token"
REMOTE_SESSION_VALIDATE_ROUTE_KEY = "auth.remote.validate.session"
EXTERNAL_AUTH_FORWARD_ROUTE_KEY = "auth.external.forward.user_password"
BUSINESS_FORWARD_ROUTE_KEY = "business.forward.generic"
TRUSTED_INTERNAL_CALL_METADATA_KEY = "trusted_internal_call"


BOOTSTRAP_INIT_PATH = "/bms.auth.v1.AuthAuthorityBootstrapService/InitBootstrapChallenge"
BOOTSTRAP_AUTH_PATH = "/bms.auth.v1.AuthAuthorityBootstrapService/AuthenticateBootstrap"
REMOTE_VERIFY_PATH = "/bms.auth.v1.AuthAuthorityRemoteAuthService/VerifyToken"
REMOTE_SESSION_PATH = "/bms.auth.v1.AuthAuthorityRemoteAuthService/ValidateSession"
EXTERNAL_AUTH_PATH = "/bms.auth.v1.AuthAuthorityExternalAuthService/ForwardUserPassword"


class RoutingPayloadPipelineService(IRoutingPayloadPipeline):
    """data_worker 通信下层：负责路由分类与出站载荷规划。"""

    def __init__(
        self,
        *,
        registry_service: IRegistryManager | None,
        auth_authority_service: str = DEFAULT_AUTH_AUTHORITY_SERVICE,
        run_mode: str = "development",
    ) -> None:
        self._registry_service = registry_service
        resolved_authority = (auth_authority_service or "").strip()
        self._auth_authority_service = (
            resolved_authority or DEFAULT_AUTH_AUTHORITY_SERVICE
        )
        self._run_mode = (run_mode or "").strip().lower() or "development"

    async def resolve_route_profile(self, flow: FlowRouteInput) -> RouteProfile:
        if flow is None:
            raise ValueError("flow route input is required")

        category = await self.classify_flow(flow)
        target_service_name = self._resolve_target_service_name(flow, category)
        target_endpoint = ""

        if target_service_name and self._registry_service is not None:
            target = await self._registry_service.choose_endpoint(
                service_name=target_service_name,
                affinity_key=self._resolve_affinity_key(flow),
                require_tags=self._resolve_required_tags(flow),
            )
            if target is not None:
                target_endpoint = (target.endpoint or "").strip()

        return RouteProfile(
            target_service_type=self._resolve_target_service_type(target_service_name),
            target_service_name=target_service_name,
            target_endpoint=target_endpoint,
            flow_category=category,
            security_policy=self._resolve_security_policy(category),
        )

    async def classify_flow(self, flow: FlowRouteInput) -> FlowCategory:
        if flow is None:
            raise ValueError("flow route input is required")

        route_key = (flow.route_key or "").strip().lower()
        if route_key:
            parsed = _parse_route_key(route_key)
            if parsed is not None:
                return parsed

        parsed_static = _parse_static_flow_category(flow)
        if parsed_static is not None:
            return parsed_static

        raise RuntimeError("route rule not found")

    async def build_outbound_payload(
        self,
        req: BuildOutboundPayloadRequest,
    ) -> OutboundPayloadPlan:
        if req is None or req.flow is None:
            raise ValueError("outbound payload request is invalid")

        profile = await self.resolve_route_profile(req.flow)
        target = await self._resolve_preferred_or_discovered_target(req, profile)
        if target is not None and not profile.target_endpoint.strip():
            profile.target_endpoint = (target.endpoint or "").strip()

        if self._requires_target_endpoint(profile.flow_category):
            if not profile.target_service_name.strip():
                raise RuntimeError("route target service is unresolved")
            if not profile.target_endpoint.strip():
                raise RuntimeError("route target endpoint is unresolved")

        return OutboundPayloadPlan(
            route_profile=profile,
            target=target,
            plain_payload=req.plain_payload,
        )

    async def _resolve_preferred_or_discovered_target(
        self,
        req: BuildOutboundPayloadRequest,
        profile: RouteProfile,
    ) -> ServiceInstance | None:
        if req.preferred_target is not None:
            return req.preferred_target

        if self._registry_service is None or not profile.target_service_name.strip():
            return None

        return await self._registry_service.choose_endpoint(
            service_name=profile.target_service_name,
            affinity_key=self._resolve_affinity_key(req.flow),
            require_tags=self._resolve_required_tags(req.flow),
        )

    def _resolve_target_service_name(
        self,
        flow: FlowRouteInput,
        category: FlowCategory,
    ) -> str:
        if _is_trusted_internal_call(flow):
            hint = (flow.target_service_hint or "").strip()
            if hint:
                return hint

        metadata = dict(flow.metadata or {})
        target = (metadata.get("target_service", "") or "").strip()
        if target:
            return target

        if category in {
            "bootstrap_call",
            "remote_auth_verify",
            "external_auth_forward",
        }:
            return self._auth_authority_service

        return ""

    def _resolve_target_service_type(self, target_service_name: str) -> TargetServiceType:
        if not target_service_name.strip():
            return "unknown"
        if target_service_name.strip().lower() == self._auth_authority_service.lower():
            return "auth_authority"
        return "internal_service"

    def _resolve_security_policy(self, category: FlowCategory) -> SecurityPolicy:
        if self._run_mode == "no_auth":
            return "disabled"

        if category == "bootstrap_call":
            return "optional"
        if category in {
            "remote_auth_verify",
            "external_auth_forward",
            "business_forward",
        }:
            return "required"
        return "optional"

    @staticmethod
    def _resolve_affinity_key(flow: FlowRouteInput) -> str:
        metadata = dict(flow.metadata or {})
        affinity = (metadata.get("affinity_key", "") or "").strip()
        if affinity:
            return affinity
        return (flow.source_service or "").strip()

    @staticmethod
    def _resolve_required_tags(flow: FlowRouteInput) -> list[str] | None:
        metadata = dict(flow.metadata or {})
        raw = (metadata.get("require_tags", "") or "").strip()
        if not raw:
            return None
        tags = [item.strip() for item in raw.split(",") if item.strip()]
        return tags or None

    @staticmethod
    def _requires_target_endpoint(category: FlowCategory) -> bool:
        return category in {
            "bootstrap_call",
            "remote_auth_verify",
            "external_auth_forward",
        }


def _parse_route_key(raw: str) -> FlowCategory | None:
    resolved = (raw or "").strip().lower()
    if resolved in {BOOTSTRAP_CHALLENGE_ROUTE_KEY, BOOTSTRAP_AUTH_ROUTE_KEY}:
        return "bootstrap_call"
    if resolved in {REMOTE_AUTH_VERIFY_ROUTE_KEY, REMOTE_SESSION_VALIDATE_ROUTE_KEY}:
        return "remote_auth_verify"
    if resolved == EXTERNAL_AUTH_FORWARD_ROUTE_KEY:
        return "external_auth_forward"
    if resolved == BUSINESS_FORWARD_ROUTE_KEY:
        return "business_forward"
    return None


def _parse_static_flow_category(flow: FlowRouteInput) -> FlowCategory | None:
    if (flow.transport or "").strip().lower() != "grpc":
        return None
    if (flow.method or "").strip().lower() != "post":
        return None

    path = (flow.path or "").strip().lower()
    if path in {BOOTSTRAP_INIT_PATH.lower(), BOOTSTRAP_AUTH_PATH.lower()}:
        return "bootstrap_call"
    if path in {REMOTE_VERIFY_PATH.lower(), REMOTE_SESSION_PATH.lower()}:
        return "remote_auth_verify"
    if path == EXTERNAL_AUTH_PATH.lower():
        return "external_auth_forward"
    return None


def _is_trusted_internal_call(flow: FlowRouteInput) -> bool:
    metadata = dict(flow.metadata or {})
    raw = (metadata.get(TRUSTED_INTERNAL_CALL_METADATA_KEY, "") or "").strip().lower()
    return raw in {"true", "1", "yes", "internal"}
