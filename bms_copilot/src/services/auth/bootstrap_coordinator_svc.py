from __future__ import annotations

import time
from typing import cast
from uuid import uuid4

from src.iface.auth.authority_client import TokenRefreshRequest
from src.iface.auth.bootstrap_coordinator import IBootstrapCoordinator
from src.iface.common.key_manager import ISecretKeyManager
from src.iface.common.local_credential_manager import (
    ILocalCredentialManager,
    ModuleCredentialSnapshot,
)
from src.iface.communication.routing_contract import FlowRouteInput
from src.iface.communication.traffic_station import (
    ITrafficStation,
    OutboundTrafficRequest,
)
from src.models.auth.auth import IssuedToken, TokenBundle
from src.models.auth.bootstrap import ChallengeRequest
from src.models.common.entry_type import EntityType
from src.models.sys.config import RuntimeConfig, SecretKeyStartupParams
from src.services.communication.rpc_client.auth_authority_bootstrap_rpc_client import (
    BOOTSTRAP_AUTH_METHOD,
    AuthAuthorityBootstrapRPCClient,
)
from src.services.communication.rpc_client.auth_authority_token_refresh_rpc_client import (
    AuthAuthorityTokenRefreshRPCClient,
)
from src.services.communication.routing_payload_pipeline_svc import (
    MODULE_TOKEN_REFRESH_ROUTE_KEY,
    TOKEN_REFRESH_PATH,
)
from src.services.common.local_credential_svc import is_credential_valid_for_discovery


DEFAULT_AUTH_AUTHORITY_SERVICE = "certification_server"
BOOTSTRAP_AUTH_ROUTE_KEY = "auth.bootstrap.authenticate"


class BootstrapCoordinatorService(IBootstrapCoordinator):
    """bms_copilot 的模块级 bootstrap / refresh / revoke 协调器。"""

    def __init__(
        self,
        *,
        runtime_cfg: RuntimeConfig,
        startup_params: SecretKeyStartupParams,
        traffic_station: ITrafficStation,
        local_credential_manager: ILocalCredentialManager,
        secret_key_service: ISecretKeyManager,
        auth_authority_service: str = DEFAULT_AUTH_AUTHORITY_SERVICE,
        refresh_leeway_sec: int = 60,
    ) -> None:
        self._runtime_cfg = runtime_cfg
        self._startup_params = startup_params
        self._traffic_station = traffic_station
        self._local_credential_manager = local_credential_manager
        self._secret_key_service = secret_key_service
        self._refresh_leeway_sec = max(int(refresh_leeway_sec), 0)
        resolved_authority = (auth_authority_service or "").strip()
        self._auth_authority_service = (
            resolved_authority or DEFAULT_AUTH_AUTHORITY_SERVICE
        )

    async def ensure_module_ready(self) -> ModuleCredentialSnapshot | None:
        if self._runtime_cfg.run_mode == "no_auth":
            return None

        snapshot = await self._bootstrap_snapshot()
        if snapshot is None:
            raise RuntimeError("bootstrap credential snapshot is missing after bootstrap")
        return snapshot

    async def refresh_module_credential(self) -> ModuleCredentialSnapshot | None:
        if self._runtime_cfg.run_mode == "no_auth":
            return None

        snapshot = await self._local_credential_manager.load_active_credential(
            self.principal_id()
        )
        if snapshot is None:
            raise RuntimeError("credential snapshot is missing")

        refreshed = await self._refresh_snapshot(snapshot)
        if refreshed is None:
            raise RuntimeError("refreshed credential snapshot is nil")
        return refreshed

    async def revoke_module_credential(self, reason: str = "") -> None:
        if self._runtime_cfg.run_mode == "no_auth":
            return None
        await self._local_credential_manager.mark_credential_expired(
            self.principal_id(),
            reason,
        )

    async def _bootstrap_snapshot(self) -> ModuleCredentialSnapshot:
        active_key_id = (self._startup_params.active_key_id or "").strip()
        instance_id = (self._runtime_cfg.instance_id or "").strip()
        if not active_key_id and not instance_id:
            raise ValueError(
                "bootstrap identity requires active_key_id or instance_id (entity_id)"
            )

        authority_endpoint = await self._resolve_bootstrap_authority_endpoint(
            self._runtime_cfg
        )
        challenge_request = _build_bootstrap_challenge_request(
            runtime_cfg=self._runtime_cfg,
            startup_params=self._startup_params,
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
            self._runtime_cfg.entity_type or "service"
        ).strip().lower() or "service"
        entity_id = instance_id or self._runtime_cfg.service_name
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

        await self._local_credential_manager.save_bootstrap_credential(
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
                    "run_mode": self._runtime_cfg.run_mode,
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
        loaded_snapshot = await self._local_credential_manager.load_active_credential(
            principal_id
        )
        if loaded_snapshot is None:
            raise RuntimeError("bootstrap credential snapshot is missing after save")
        if not is_credential_valid_for_discovery(loaded_snapshot, now=time.time()):
            raise RuntimeError("bootstrap credential is not valid for discovery")
        return loaded_snapshot

    async def _resolve_bootstrap_authority_endpoint(
        self,
        runtime_cfg: RuntimeConfig,
    ) -> str:
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
            cached_endpoint = await self._load_cached_authority_endpoint()
            if cached_endpoint:
                return cached_endpoint
            raise RuntimeError("auth authority is not discoverable")

        target_endpoint = (dispatch.target_endpoint or "").strip()
        if not target_endpoint:
            cached_endpoint = await self._load_cached_authority_endpoint()
            if cached_endpoint:
                return cached_endpoint
            raise RuntimeError("auth authority endpoint is empty")
        return target_endpoint

    async def _load_cached_authority_endpoint(self) -> str:
        try:
            snapshot = await self._local_credential_manager.load_active_credential(
                self.principal_id()
            )
        except Exception:
            return ""

        if snapshot is None:
            return ""
        metadata = dict(snapshot.metadata or {})
        return str(metadata.get("auth_authority_ep") or "").strip()

    async def _refresh_snapshot(
        self,
        snapshot: ModuleCredentialSnapshot,
    ) -> ModuleCredentialSnapshot:
        if snapshot is None:
            raise RuntimeError("credential snapshot is nil")
        if snapshot.tokens is None or snapshot.tokens.refresh_token is None:
            raise RuntimeError("refresh token bundle is missing")
        refresh_token_raw = (snapshot.tokens.refresh_token.raw or "").strip()
        if not refresh_token_raw:
            raise RuntimeError("refresh token raw is missing")

        endpoint = await self._refresh_authority_endpoint(snapshot)
        if endpoint == "":
            raise RuntimeError("auth authority refresh endpoint is missing")

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

    async def _refresh_authority_endpoint(
        self,
        snapshot: ModuleCredentialSnapshot,
    ) -> str:
        endpoint = (snapshot.metadata or {}).get("auth_authority_ep", "").strip()
        if endpoint:
            return endpoint

        principal_id = snapshot.principal_id.strip() or self.principal_id()
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
            return ""

        target_endpoint = (dispatch.target_endpoint or "").strip()
        if target_endpoint and snapshot.metadata is not None:
            snapshot.metadata["auth_authority_ep"] = target_endpoint
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
            or self.principal_id()
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
            or f"bms_copilot/{self._runtime_cfg.service_name or 'service'}"
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

    def principal_id(self) -> str:
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
                or "bms_copilot"
            ).strip()
        return f"{entity_type}:{entity_id}"


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
            startup_params.entity_name or runtime_cfg.service_name or "bms_copilot"
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
        user_agent=f"bms_copilot/{audience}",
        request_id=request_id,
        trace_id=request_id,
        ttl_sec=60,
    )


def _normalize_bootstrap_entity_type(raw: str) -> EntityType:
    normalized = (raw or "").strip().lower()
    if normalized in {"service", "user", "device"}:
        return cast(EntityType, normalized)
    return cast(EntityType, "service")


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
