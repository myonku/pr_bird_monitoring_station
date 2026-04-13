import asyncio
import contextlib
from time import time
from uuid import UUID

from src.iface.common.registry_manager import IRegistryManager
from src.models.common.instance import ServiceInstance, ServiceSnapshot
from src.repo.etcd_client import (
    EtcdAsyncClient,
    build_prefix,
    build_service_key,
    decode_instance,
    encode_instance,
)
from src.utils.selector_policy import (
    filter_by_tags,
    pick_hash_affinity,
    pick_round_robin,
    random_weighted,
)


class RegistryService(IRegistryManager):
    """服务注册与发现快照服务。"""

    def __init__(
        self,
        etcd_client: EtcdAsyncClient | None = None,
        max_stale_ms: int = 30_000,
    ):
        self._services: dict[str, dict[UUID, ServiceInstance]] = {}
        self._revision = 0
        self._rr_counter = 0
        self._etcd_client = etcd_client
        self._lease_stop_events: dict[str, asyncio.Event] = {}
        self._lease_tasks: dict[str, asyncio.Task[None]] = {}
        self._max_stale_ms = max(max_stale_ms, 1_000)

    @staticmethod
    def _now_ms() -> int:
        return int(time() * 1000)

    @staticmethod
    def _instance_ref(service_name: str, instance_id: UUID) -> str:
        return f"{service_name}::{instance_id}"

    async def _stop_registration_maintenance(self, instance_ref: str) -> None:
        stop_event = self._lease_stop_events.pop(instance_ref, None)
        if stop_event is not None:
            stop_event.set()

        task = self._lease_tasks.pop(instance_ref, None)
        if task is not None:
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await task

    async def _refresh_instance_heartbeat(
        self,
        service_name: str,
        instance_id: UUID,
        ttl: int,
        key: str,
    ) -> bool:
        bucket = self._services.get(service_name)
        if not bucket:
            return False

        current = bucket.get(instance_id)
        if current is None:
            return False

        refreshed = ServiceInstance(
            id=current.id,
            service_id=current.service_id,
            name=current.name,
            endpoint=current.endpoint,
            heartbeat=self._now_ms(),
            zone=current.zone,
            version=current.version,
            weight=max(current.weight, 1),
            tags=list(current.tags),
            active_comm_key_id=current.active_comm_key_id,
            metadata=dict(current.metadata),
        )
        bucket[instance_id] = refreshed

        if self._etcd_client is None:
            return True
        await self._etcd_client.put_with_lease(
            key,
            encode_instance(refreshed),
            ttl=ttl,
        )
        return True

    async def _maintain_registration(
        self,
        service_name: str,
        instance_id: UUID,
        instance_ref: str,
        ttl: int,
        key: str,
        stop_event: asyncio.Event,
    ) -> None:
        if self._etcd_client is None:
            return

        keepalive_task = asyncio.create_task(
            self._etcd_client.keepalive_forever(ttl, stop_event)
        )
        interval_sec = max(ttl // 2, 1)

        try:
            while not stop_event.is_set():
                await asyncio.sleep(interval_sec)
                if stop_event.is_set():
                    break

                with contextlib.suppress(Exception):
                    alive = await self._refresh_instance_heartbeat(
                        service_name=service_name,
                        instance_id=instance_id,
                        ttl=ttl,
                        key=key,
                    )
                    if not alive:
                        break
        finally:
            stop_event.set()
            keepalive_task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await keepalive_task

            current = asyncio.current_task()
            if self._lease_tasks.get(instance_ref) is current:
                self._lease_tasks.pop(instance_ref, None)
            if self._lease_stop_events.get(instance_ref) is stop_event:
                self._lease_stop_events.pop(instance_ref, None)

    async def register(self, instance: ServiceInstance, ttl_sec: int) -> None:
        if instance.name == "":
            raise ValueError("service instance name is required")
        if instance.endpoint == "":
            raise ValueError("service instance endpoint is required")

        normalized = ServiceInstance(
            id=instance.id,
            service_id=instance.service_id,
            name=instance.name,
            endpoint=instance.endpoint,
            heartbeat=instance.heartbeat if instance.heartbeat > 0 else self._now_ms(),
            zone=instance.zone,
            version=instance.version,
            weight=max(instance.weight, 1),
            tags=list(instance.tags),
            active_comm_key_id=instance.active_comm_key_id,
            metadata=dict(instance.metadata),
        )

        instance_ref = self._instance_ref(normalized.name, normalized.id)
        await self._stop_registration_maintenance(instance_ref)

        service_bucket = self._services.setdefault(normalized.name, {})
        service_bucket[normalized.id] = normalized
        self._revision += 1

        if self._etcd_client is None:
            return

        key = build_service_key(
            self._etcd_client.namespace, normalized.name, str(normalized.id)
        )
        ttl = ttl_sec if ttl_sec > 0 else 30
        await self._etcd_client.put_with_lease(
            key, encode_instance(normalized), ttl=ttl
        )

        stop_event = asyncio.Event()
        self._lease_stop_events[instance_ref] = stop_event
        self._lease_tasks[instance_ref] = asyncio.create_task(
            self._maintain_registration(
                service_name=normalized.name,
                instance_id=normalized.id,
                instance_ref=instance_ref,
                ttl=ttl,
                key=key,
                stop_event=stop_event,
            )
        )

    async def unregister(self, instance: ServiceInstance) -> None:
        if instance.name == "":
            raise ValueError("service instance name is required")

        instance_ref = self._instance_ref(instance.name, instance.id)
        await self._stop_registration_maintenance(instance_ref)

        service_bucket = self._services.get(instance.name)
        if not service_bucket:
            return
        service_bucket.pop(instance.id, None)
        if not service_bucket:
            self._services.pop(instance.name, None)
        self._revision += 1

        if self._etcd_client is None:
            return
        key = build_service_key(
            self._etcd_client.namespace, instance.name, str(instance.id)
        )
        with contextlib.suppress(Exception):
            await self._etcd_client.delete(key)

    async def get_service_instances(self, service_name: str) -> list[ServiceInstance]:
        if service_name == "":
            raise ValueError("service name is required")

        if self._etcd_client is not None:
            prefix = build_prefix(self._etcd_client.namespace, service_name)
            with contextlib.suppress(Exception):
                revision, items = await self._etcd_client.get_prefix_with_revision(prefix)
                instances: list[ServiceInstance] = []
                for _, value in items:
                    with contextlib.suppress(Exception):
                        inst = decode_instance(value)
                        instances.append(inst)
                instances.sort(key=lambda item: str(item.id))
                if instances:
                    self._services[service_name] = {inst.id: inst for inst in instances}
                else:
                    self._services.pop(service_name, None)
                self._revision = max(self._revision, revision)
                return instances

        service_bucket = self._services.get(service_name, {})
        instances = list(service_bucket.values())
        instances.sort(key=lambda item: str(item.id))
        return instances

    async def get_service_snapshot(self, service_name: str) -> ServiceSnapshot | None:
        if service_name == "":
            raise ValueError("service name is required")

        instances = await self.get_service_instances(service_name)
        return ServiceSnapshot(
            name=service_name,
            instances=instances,
            revision=self._revision,
        )

    async def choose_endpoint(
        self,
        service_name: str,
        affinity_key: str = "",
        require_tags: list[str] | None = None,
    ) -> ServiceInstance | None:
        instances = await self.get_service_instances(service_name)
        if not instances:
            return None

        now = self._now_ms()
        live_instances = [
            inst
            for inst in instances
            if inst.heartbeat <= 0 or now - inst.heartbeat <= self._max_stale_ms
        ]
        candidates = filter_by_tags(live_instances, require_tags or [])
        if not candidates:
            return None

        if affinity_key:
            return pick_hash_affinity(candidates, affinity_key)

        selected = random_weighted(candidates)
        if selected is not None:
            return selected
        selected = pick_round_robin(candidates, self._rr_counter)
        self._rr_counter += 1
        return selected
