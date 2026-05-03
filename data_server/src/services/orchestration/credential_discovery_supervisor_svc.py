from __future__ import annotations

import asyncio
import contextlib
import logging
import time
from collections.abc import Callable

from src.iface.auth.bootstrap_coordinator import IBootstrapCoordinator
from src.iface.common.local_credential_manager import (
    ILocalCredentialManager,
    ModuleCredentialSnapshot,
)
from src.iface.common.registry_manager import IRegistryManager
from src.models.common.instance import ServiceInstance
from src.models.sys.config import RuntimeConfig
from src.services.common.local_credential_svc import (
    is_credential_refresh_due,
    is_credential_valid_for_discovery,
)


DEFAULT_REGISTRY_TTL_SEC = 30
DEFAULT_REFRESH_POLL_INTERVAL_SEC = 30
DEFAULT_REFRESH_LEEWAY_SEC = 60


class CredentialDiscoverySupervisorService:
    """data_server 运行期凭证与服务发现闭环监督器。"""

    def __init__(
        self,
        *,
        runtime_cfg: RuntimeConfig,
        local_credential_manager: ILocalCredentialManager,
        registry_service: IRegistryManager,
        service_instance_factory: Callable[[str], ServiceInstance],
        bootstrap_coordinator: IBootstrapCoordinator,
        registry_ttl_sec: int = DEFAULT_REGISTRY_TTL_SEC,
        refresh_poll_interval_sec: int = DEFAULT_REFRESH_POLL_INTERVAL_SEC,
        refresh_leeway_sec: int = DEFAULT_REFRESH_LEEWAY_SEC,
    ) -> None:
        self._runtime_cfg = runtime_cfg
        self._local_credential_manager = local_credential_manager
        self._registry_service = registry_service
        self._bootstrap_coordinator = bootstrap_coordinator
        self._service_instance_factory = service_instance_factory
        self._registry_ttl_sec = max(int(registry_ttl_sec), 1)
        self._refresh_poll_interval_sec = max(int(refresh_poll_interval_sec), 1)
        self._refresh_leeway_sec = max(int(refresh_leeway_sec), 0)
        self._logger = logging.getLogger("credential_supervisor")

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

            with contextlib.suppress(Exception):
                await self._bootstrap_coordinator.revoke_module_credential(
                    "missing_snapshot" if snapshot is None else "invalid_snapshot"
                )
            snapshot = await self._bootstrap_and_load_snapshot()
            return await self._ensure_registered(snapshot, registered_instance)

        if is_credential_refresh_due(
            snapshot,
            now=now,
            refresh_leeway_sec=self._refresh_leeway_sec,
        ):
            try:
                refreshed_snapshot = (
                    await self._bootstrap_coordinator.refresh_module_credential()
                )
                if refreshed_snapshot is None:
                    raise RuntimeError("refreshed credential snapshot is missing")
                snapshot = refreshed_snapshot
            except Exception as exc:
                self._logger.warning(
                    "stage=credential_refresh_failed service=%s principal_id=%s reason=%s",
                    self._runtime_cfg.service_name,
                    principal_id,
                    exc,
                )
                with contextlib.suppress(Exception):
                    await self._bootstrap_coordinator.revoke_module_credential(
                        reason=str(exc)
                    )
                if registered_instance is not None:
                    with contextlib.suppress(Exception):
                        await self._registry_service.unregister(registered_instance)
                    registered_instance = None
                snapshot = await self._bootstrap_and_load_snapshot()
                return await self._ensure_registered(snapshot, registered_instance)

        return await self._ensure_registered(snapshot, registered_instance)

    async def _bootstrap_and_load_snapshot(self) -> ModuleCredentialSnapshot:
        snapshot = await self._bootstrap_coordinator.ensure_module_ready()
        if snapshot is None:
            raise RuntimeError("bootstrap credential snapshot missing after bootstrap")
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

    def _principal_id(self) -> str:
        entity_type = (
            self._runtime_cfg.entity_type or "service"
        ).strip().lower() or "service"
        entity_id = (
            self._runtime_cfg.instance_id or self._runtime_cfg.service_name or ""
        ).strip()
        if not entity_id:
            entity_id = (self._runtime_cfg.service_name or "data_server").strip()
        return f"{entity_type}:{entity_id}"
