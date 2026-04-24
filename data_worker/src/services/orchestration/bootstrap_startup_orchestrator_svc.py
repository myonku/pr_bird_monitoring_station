from __future__ import annotations

from dataclasses import dataclass
from uuid import uuid4
import time
from typing import cast

from src.iface.common.local_credential_manager import (
    ILocalCredentialManager,
    ModuleCredentialSnapshot,
)
from src.iface.communication.routing_contract import FlowRouteInput
from src.iface.communication.traffic_station import (
    ITrafficStation,
    OutboundTrafficRequest,
)
from src.models.common.entry_type import EntityType
from src.models.auth.bootstrap import ChallengeRequest
from src.models.sys.config import RuntimeConfig, SecretKeyStartupParams
from src.services.communication.rpc_client.auth_authority_bootstrap_rpc_client import (
    BOOTSTRAP_AUTH_METHOD,
    AuthAuthorityBootstrapRPCClient,
)
from src.services.common.secret_key_svc import SecretKeyService


DEFAULT_AUTH_AUTHORITY_SERVICE = "certification_server"
BOOTSTRAP_AUTH_ROUTE_KEY = "auth.bootstrap.authenticate"


@dataclass(slots=True, kw_only=True)
class BootstrapStartupResult:
    stage: str
    authority_endpoint: str
    credential_key: str


class BootstrapStartupOrchestratorService:
    """将 data_worker 启动期 bootstrap 流程下沉到编排层。"""

    def __init__(
        self,
        *,
        traffic_station: ITrafficStation,
        local_credential_manager: ILocalCredentialManager,
        secret_key_service: SecretKeyService,
        auth_authority_service: str = DEFAULT_AUTH_AUTHORITY_SERVICE,
    ) -> None:
        self._traffic_station = traffic_station
        self._local_credential_manager = local_credential_manager
        self._secret_key_service = secret_key_service
        resolved_authority = (auth_authority_service or "").strip()
        self._auth_authority_service = (
            resolved_authority or DEFAULT_AUTH_AUTHORITY_SERVICE
        )

    async def ensure_ready(
        self,
        *,
        runtime_cfg: RuntimeConfig,
        startup_params: SecretKeyStartupParams,
    ) -> BootstrapStartupResult:
        if runtime_cfg is None:
            raise ValueError("runtime config is required")
        if startup_params is None:
            raise ValueError("startup params are required")
        if self._traffic_station is None:
            raise RuntimeError("traffic station dependencies are required")
        if self._local_credential_manager is None:
            raise RuntimeError("module credential manager dependencies are required")

        active_key_id = (startup_params.active_key_id or "").strip()
        instance_id = (runtime_cfg.instance_id or "").strip()
        if not active_key_id and not instance_id:
            raise ValueError(
                "bootstrap identity requires active_key_id or instance_id (entity_id)"
            )

        authority_endpoint = await self._resolve_authority_endpoint(runtime_cfg)
        challenge_request = _build_bootstrap_challenge_request(
            runtime_cfg=runtime_cfg,
            startup_params=startup_params,
        )
        private_key_ref = await self._secret_key_service.get_private_key_ref()

        bootstrap_client = AuthAuthorityBootstrapRPCClient(authority_endpoint)
        result = await bootstrap_client.execute_bootstrap_handshake(
            challenge_request=challenge_request,
            private_key_pem=private_key_ref.private_key_ref.encode("utf-8"),
            role="service",
            scopes=["service:bootstrap"],
            require_downstream_token=False,
        )
        if (result.stage or "").strip().lower() != "ready":
            raise RuntimeError(
                f"bootstrap handshake stage is not ready: {result.stage}"
            )

        entity_type = (
            runtime_cfg.entity_type or "service"
        ).strip().lower() or "service"
        entity_id = instance_id or runtime_cfg.service_name
        now = time.time()
        resolved_key_id = (
            (result.active_comm_key_id or "").strip() or active_key_id or instance_id
        )
        principal_id = (
            result.identity.principal_id
            if result.identity is not None and result.identity.principal_id
            else f"{entity_type}:{entity_id}"
        )
        issued_at = result.issued_at if result.issued_at > 0 else now
        expires_at = result.expires_at if result.expires_at > 0 else now + 900
        credential_key = await self._local_credential_manager.save_bootstrap_credential(
            ModuleCredentialSnapshot(
                principal_id=principal_id,
                stage="ready",
                identity=result.identity,
                session=result.session,
                tokens=result.tokens,
                active_comm_key_id=resolved_key_id,
                issued_at=issued_at,
                expires_at=expires_at,
                updated_at=now,
                metadata={
                    "run_mode": runtime_cfg.run_mode,
                    "auth_authority": self._auth_authority_service,
                    "auth_authority_ep": authority_endpoint,
                    "credential_status": "active",
                    "bootstrap_rpc_stage": result.stage,
                    "bootstrap_principal_id": principal_id,
                    "bootstrap_active_comm_key_id": resolved_key_id,
                    "bootstrap_issued_at": str(issued_at),
                    "bootstrap_expires_at": str(expires_at),
                },
            )
        )
        if not credential_key:
            raise RuntimeError("save bootstrap credential returned empty key")

        return BootstrapStartupResult(
            stage=result.stage,
            authority_endpoint=authority_endpoint,
            credential_key=credential_key,
        )

    async def _resolve_authority_endpoint(self, runtime_cfg: RuntimeConfig) -> str:
        instance_id = (runtime_cfg.instance_id or "").strip()
        dispatch = await self._traffic_station.send_outbound(
            OutboundTrafficRequest(
                flow=FlowRouteInput(
                    route_key=BOOTSTRAP_AUTH_ROUTE_KEY,
                    transport="grpc",
                    method="POST",
                    path=BOOTSTRAP_AUTH_METHOD,
                    source_service=(runtime_cfg.service_name or "").strip(),
                    target_service_hint=self._auth_authority_service,
                    metadata={
                        "startup_phase": "bootstrap",
                        "affinity_key": instance_id,
                        "trusted_internal_call": "true",
                    },
                ),
                headers={},
                payload="",
            )
        )
        if dispatch is None:
            raise RuntimeError("auth authority is not discoverable")

        target_endpoint = (dispatch.target_endpoint or "").strip()
        if not target_endpoint:
            raise RuntimeError("auth authority endpoint is empty")
        return target_endpoint


def _build_bootstrap_challenge_request(
    *,
    runtime_cfg: RuntimeConfig,
    startup_params: SecretKeyStartupParams,
) -> ChallengeRequest:
    entity_type = (
        runtime_cfg.entity_type or startup_params.entity_type or "service"
    ).strip().lower() or "service"
    entity_id = (
        runtime_cfg.instance_id
        or startup_params.entity_id
        or startup_params.instance_id
        or runtime_cfg.service_name
        or ""
    ).strip()
    if not entity_id:
        entity_id = (
            startup_params.entity_name or runtime_cfg.service_name or "data_worker"
        ).strip()
    key_id = (
        startup_params.active_key_id or startup_params.instance_id or entity_id
    ).strip()
    if not key_id:
        key_id = entity_id
    audience = (
        runtime_cfg.service_name or startup_params.entity_name or entity_id
    ).strip()
    if not audience:
        audience = entity_id
    request_id = uuid4().hex

    return ChallengeRequest(
        entity_type=_normalize_bootstrap_entity_type(entity_type),
        entity_id=entity_id,
        key_id=key_id,
        audience=audience,
        client_id=(
            startup_params.instance_name or runtime_cfg.service_name or entity_id
        ).strip(),
        gateway_id=(startup_params.entity_name or "").strip(),
        source_ip="127.0.0.1",
        user_agent=f"data_worker/{audience}",
        request_id=request_id,
        trace_id=request_id,
        ttl_sec=60,
    )


def _normalize_bootstrap_entity_type(raw: str) -> EntityType:
    normalized = (raw or "").strip().lower()
    if normalized in {"service", "user", "device"}:
        return cast(EntityType, normalized)
    return cast(EntityType, "service")
