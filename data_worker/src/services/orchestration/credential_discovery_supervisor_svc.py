from __future__ import annotations

import asyncio
import contextlib
import logging
import time
from collections.abc import Callable
from uuid import uuid4

from src.iface.auth.authority_client import TokenRefreshRequest
from src.iface.common.local_credential_manager import (
    ILocalCredentialManager,
    ModuleCredentialSnapshot,
)
from src.iface.common.registry_manager import IRegistryManager
from src.iface.communication.routing_contract import FlowRouteInput
from src.iface.communication.traffic_station import (
    ITrafficStation,
    OutboundTrafficRequest,
)
from src.models.auth.auth import IssuedToken, TokenBundle
from src.models.common.instance import ServiceInstance
from src.models.sys.config import RuntimeConfig, SecretKeyStartupParams
from src.services.common.local_credential_svc import (
    is_credential_refresh_due,
    is_credential_valid_for_discovery,
)
from src.services.common.secret_key_svc import SecretKeyService
from src.services.communication.rpc_client.auth_authority_token_refresh_rpc_client import (
    AuthAuthorityTokenRefreshRPCClient,
)
from src.services.orchestration.bootstrap_startup_orchestrator_svc import (
    BootstrapStartupOrchestratorService,
    DEFAULT_AUTH_AUTHORITY_SERVICE,
)
from src.services.communication.routing_payload_pipeline_svc import (
    MODULE_TOKEN_REFRESH_ROUTE_KEY,
    TOKEN_REFRESH_PATH,
)


DEFAULT_REGISTRY_TTL_SEC = 30
DEFAULT_REFRESH_POLL_INTERVAL_SEC = 30
DEFAULT_REFRESH_LEEWAY_SEC = 60


class CredentialDiscoverySupervisorService:
    """data_worker 运行期凭证与服务发现闭环监督器。"""

    def __init__(
        self,
        *,
        runtime_cfg: RuntimeConfig,
        startup_params: SecretKeyStartupParams,
        traffic_station: ITrafficStation,
        local_credential_manager: ILocalCredentialManager,
        registry_service: IRegistryManager,
        secret_key_service: SecretKeyService,
        service_instance_factory: Callable[[str], ServiceInstance],
        auth_authority_service: str = DEFAULT_AUTH_AUTHORITY_SERVICE,
        registry_ttl_sec: int = DEFAULT_REGISTRY_TTL_SEC,
        refresh_poll_interval_sec: int = DEFAULT_REFRESH_POLL_INTERVAL_SEC,
        refresh_leeway_sec: int = DEFAULT_REFRESH_LEEWAY_SEC,
    ) -> None:
        self._runtime_cfg = runtime_cfg
        self._startup_params = startup_params
        self._traffic_station = traffic_station
        self._local_credential_manager = local_credential_manager
        self._registry_service = registry_service
        self._secret_key_service = secret_key_service
        self._service_instance_factory = service_instance_factory
        self._auth_authority_service = (
            auth_authority_service or ""
        ).strip() or DEFAULT_AUTH_AUTHORITY_SERVICE
        self._registry_ttl_sec = max(int(registry_ttl_sec), 1)
        self._refresh_poll_interval_sec = max(int(refresh_poll_interval_sec), 1)
        self._refresh_leeway_sec = max(int(refresh_leeway_sec), 0)
        self._startup_orchestrator = BootstrapStartupOrchestratorService(
            traffic_station=traffic_station,
            local_credential_manager=local_credential_manager,
            secret_key_service=secret_key_service,
            auth_authority_service=self._auth_authority_service,
        )
        self._logger = logging.getLogger("data_worker.credential_supervisor")

    async def run(
        self,
        stop_event: asyncio.Event,
        *,
        registered_instance: ServiceInstance | None = None,
    ) -> None:
        current_registered_instance = registered_instance
        while not stop_event.is_set():
            try:
                current_registered_instance = await self._reconcile_once(
                    current_registered_instance
                )
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                self._logger.warning(
                    "stage=credential_supervisor_reconcile_failed service=%s reason=%s",
                    self._runtime_cfg.service_name,
                    exc,
                )

            if stop_event.is_set():
                break

            with contextlib.suppress(asyncio.TimeoutError):
                await asyncio.wait_for(
                    stop_event.wait(),
                    timeout=self._refresh_poll_interval_sec,
                )

    async def reconcile_once(
        self,
        *,
        registered_instance: ServiceInstance | None = None,
    ) -> ServiceInstance | None:
        return await self._reconcile_once(registered_instance)

    async def _reconcile_once(
        self,
        registered_instance: ServiceInstance | None,
    ) -> ServiceInstance | None:
        principal_id = self._principal_id()
        snapshot = await self._local_credential_manager.load_active_credential(
            principal_id
        )
        now = time.time()

        if not is_credential_valid_for_discovery(snapshot, now=now):
            if registered_instance is not None:
                with contextlib.suppress(Exception):
                    await self._registry_service.unregister(registered_instance)
                registered_instance = None

            snapshot = await self._bootstrap_and_load_snapshot()
            return await self._ensure_registered(snapshot, registered_instance)

        if is_credential_refresh_due(
            snapshot,
            now=now,
            refresh_leeway_sec=self._refresh_leeway_sec,
        ):
            try:
                snapshot = await self._refresh_snapshot(snapshot)
            except Exception as exc:
                self._logger.warning(
                    "stage=credential_refresh_failed service=%s principal_id=%s reason=%s",
                    self._runtime_cfg.service_name,
                    principal_id,
                    exc,
                )
                await self._local_credential_manager.mark_credential_expired(
                    principal_id,
                    reason=str(exc),
                )
                if registered_instance is not None:
                    with contextlib.suppress(Exception):
                        await self._registry_service.unregister(registered_instance)
                    registered_instance = None
                snapshot = await self._bootstrap_and_load_snapshot()
                return await self._ensure_registered(snapshot, registered_instance)

        return await self._ensure_registered(snapshot, registered_instance)

    async def _bootstrap_and_load_snapshot(self) -> ModuleCredentialSnapshot:
        await self._startup_orchestrator.ensure_ready(
            runtime_cfg=self._runtime_cfg,
            startup_params=self._startup_params,
        )
        principal_id = self._principal_id()
        snapshot = await self._local_credential_manager.load_active_credential(
            principal_id
        )
        if snapshot is None:
            raise RuntimeError("bootstrap credential snapshot missing after bootstrap")
        return snapshot

    async def _refresh_snapshot(
        self,
        snapshot: ModuleCredentialSnapshot | None,
    ) -> ModuleCredentialSnapshot:
        if snapshot is None:
            raise RuntimeError("snapshot is None")
        if snapshot.tokens is None or snapshot.tokens.refresh_token is None:
            raise RuntimeError("refresh token bundle is missing")
        refresh_token_raw = (snapshot.tokens.refresh_token.raw or "").strip()
        if not refresh_token_raw:
            raise RuntimeError("refresh token raw is missing")

        endpoint = await self._resolve_refresh_endpoint(snapshot)
        refresh_client = AuthAuthorityTokenRefreshRPCClient(endpoint)
        refresh_request = self._build_refresh_request(snapshot)
        refreshed_bundle = await refresh_client.execute_refresh_token_bundle(
            refresh_request
        )
        merged_bundle = _merge_token_bundles(snapshot.tokens, refreshed_bundle)
        snapshot.tokens = merged_bundle

        now = time.time()
        max_ttl_sec = _max_token_ttl_sec(merged_bundle)
        if snapshot.session is not None:
            snapshot.session.updated_at = now
            snapshot.session.last_seen_at = now
            snapshot.session.last_verified_at = now
            snapshot.session.version = max(snapshot.session.version + 1, 1)
            if max_ttl_sec > 0:
                next_refresh_at = _next_refresh_at(
                    now,
                    max_ttl_sec=max_ttl_sec,
                    leeway_sec=self._refresh_leeway_sec,
                )
                if next_refresh_at > snapshot.session.next_refresh_at:
                    snapshot.session.next_refresh_at = next_refresh_at
                snapshot.session.expires_at = max(
                    snapshot.session.expires_at,
                    now + max_ttl_sec,
                )

        if snapshot.identity is not None and snapshot.session is not None:
            snapshot.identity.issued_at = now
            snapshot.identity.expires_at = max(
                snapshot.identity.expires_at,
                snapshot.session.expires_at,
            )

        snapshot.expires_at = max(
            snapshot.expires_at,
            snapshot.session.expires_at if snapshot.session is not None else 0.0,
        )
        snapshot.updated_at = now
        snapshot.metadata = dict(snapshot.metadata or {})
        snapshot.metadata["credential_status"] = "active"
        snapshot.metadata["credential_last_refresh_at"] = str(now)
        if max_ttl_sec > 0:
            snapshot.metadata["credential_last_refresh_ttl_sec"] = str(max_ttl_sec)

        await self._local_credential_manager.save_bootstrap_credential(snapshot)
        return snapshot

    async def _ensure_registered(
        self,
        snapshot: ModuleCredentialSnapshot | None,
        current_registered_instance: ServiceInstance | None,
    ) -> ServiceInstance | None:
        if snapshot is None:
            raise RuntimeError("snapshot is None")
        if snapshot.active_comm_key_id.strip() == "":
            raise RuntimeError("active communication key id is missing from snapshot")

        desired_instance = self._service_instance_factory(snapshot.active_comm_key_id)
        if (
            current_registered_instance is not None
            and current_registered_instance.id == desired_instance.id
            and current_registered_instance.active_comm_key_id
            == desired_instance.active_comm_key_id
        ):
            return current_registered_instance

        await self._registry_service.register(
            desired_instance, ttl_sec=self._registry_ttl_sec
        )
        return desired_instance

    async def _resolve_refresh_endpoint(
        self,
        snapshot: ModuleCredentialSnapshot,
    ) -> str:
        principal_id = snapshot.principal_id.strip() or self._principal_id()
        dispatch = await self._traffic_station.send_outbound(
            OutboundTrafficRequest(
                flow=FlowRouteInput(
                    route_key=MODULE_TOKEN_REFRESH_ROUTE_KEY,
                    transport="grpc",
                    method="POST",
                    path=TOKEN_REFRESH_PATH,
                    source_service=(self._runtime_cfg.service_name or "").strip(),
                    target_service_hint=self._auth_authority_service,
                    metadata={
                        "startup_phase": "credential_refresh",
                        "principal_id": principal_id,
                        "trusted_internal_call": "true",
                    },
                ),
                headers={},
                payload="",
            )
        )
        if dispatch is None:
            raise RuntimeError("auth authority refresh endpoint is not discoverable")

        target_endpoint = (dispatch.target_endpoint or "").strip()
        if not target_endpoint:
            raise RuntimeError("auth authority refresh endpoint is empty")
        return target_endpoint

    def _build_refresh_request(
        self,
        snapshot: ModuleCredentialSnapshot,
    ) -> TokenRefreshRequest:
        if snapshot.tokens is None or snapshot.tokens.refresh_token is None:
            raise RuntimeError("refresh token bundle is missing")

        identity = snapshot.identity
        session = snapshot.session
        request_id = uuid4().hex
        client_id = (
            (identity.client_id if identity is not None else "")
            or (session.client_id if session is not None else "")
            or self._runtime_cfg.service_name
            or self._principal_id()
        ).strip()
        gateway_id = (
            (identity.gateway_id if identity is not None else "")
            or (session.gateway_id if session is not None else "")
            or ""
        ).strip()
        source_ip = (
            (identity.source_ip if identity is not None else "")
            or (session.created_by_ip if session is not None else "")
            or "127.0.0.1"
        ).strip()
        user_agent = (
            (identity.user_agent if identity is not None else "")
            or (session.user_agent if session is not None else "")
            or f"data_worker/{self._runtime_cfg.service_name or 'service'}"
        ).strip()

        return TokenRefreshRequest(
            refresh_token=snapshot.tokens.refresh_token.raw,
            client_id=client_id,
            gateway_id=gateway_id,
            source_ip=source_ip,
            user_agent=user_agent,
            request_id=request_id,
            trace_id=request_id,
        )

    def _principal_id(self) -> str:
        entity_type = (
            self._runtime_cfg.entity_type or "service"
        ).strip().lower() or "service"
        entity_id = (
            self._runtime_cfg.instance_id
            or self._startup_params.instance_id
            or self._runtime_cfg.service_name
            or ""
        ).strip()
        if not entity_id:
            entity_id = (
                self._startup_params.entity_id
                or self._startup_params.entity_name
                or self._runtime_cfg.service_name
                or "data_worker"
            ).strip()
        return f"{entity_type}:{entity_id}"


def _merge_token_bundles(
    previous: TokenBundle | None, refreshed: TokenBundle
) -> TokenBundle:
    previous = previous or TokenBundle()
    return TokenBundle(
        access_token=_merge_issued_token(previous.access_token, refreshed.access_token),
        refresh_token=_merge_issued_token(
            previous.refresh_token, refreshed.refresh_token
        ),
        downstream_token=_merge_issued_token(
            previous.downstream_token, refreshed.downstream_token
        ),
    )


def _merge_issued_token(
    previous: IssuedToken | None, refreshed: IssuedToken | None
) -> IssuedToken | None:
    if refreshed is None:
        return previous
    if previous is None:
        return refreshed

    return IssuedToken(
        raw=(refreshed.raw or previous.raw).strip(),
        type=refreshed.type or previous.type,
        storage=refreshed.storage or previous.storage,
        claims=refreshed.claims if refreshed.claims is not None else previous.claims,
        ttl_sec=refreshed.ttl_sec if refreshed.ttl_sec > 0 else previous.ttl_sec,
    )


def _max_token_ttl_sec(bundle: TokenBundle | None) -> int:
    if bundle is None:
        return 0
    ttl_values = [
        token.ttl_sec
        for token in (
            bundle.access_token,
            bundle.refresh_token,
            bundle.downstream_token,
        )
        if token is not None and token.ttl_sec > 0
    ]
    if not ttl_values:
        return 0
    return max(ttl_values)


def _next_refresh_at(now: float, *, max_ttl_sec: int, leeway_sec: int) -> float:
    if max_ttl_sec <= 0:
        return now + max(leeway_sec, 1)
    if max_ttl_sec <= leeway_sec:
        return now + max(1, max_ttl_sec // 2)
    return now + max(1, max_ttl_sec - leeway_sec)
