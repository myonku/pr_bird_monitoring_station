from __future__ import annotations

import contextlib
from time import time
from uuid import UUID

from src.models.registry.instance import ServiceInstance, ServiceSnapshot
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


class RegistryService:
    """服务注册与发现快照服务。"""

    def __init__(self, etcd_client: EtcdAsyncClient | None = None):
        self._services: dict[str, dict[UUID, ServiceInstance]] = {}
        self._revision = 0
        self._rr_counter = 0
        self._etcd_client = etcd_client
        self._lease_stop_events: dict[str, object] = {}

    async def register(self, instance: ServiceInstance, ttl_sec: int) -> None:
        service_bucket = self._services.setdefault(instance.name, {})
        normalized = ServiceInstance(
            id=instance.id,
            service_id=instance.service_id,
            name=instance.name,
            endpoint=instance.endpoint,
            heartbeat_at=instance.heartbeat_at if instance.heartbeat_at > 0 else time(),
            zone=instance.zone,
            version=instance.version,
            weight=max(instance.weight, 1),
            tags=list(instance.tags),
            active_comm_key_id=instance.active_comm_key_id,
            metadata=dict(instance.metadata),
        )
        service_bucket[instance.id] = normalized
        self._revision += 1

        if self._etcd_client is None:
            return

        key = build_service_key(self._etcd_client.namespace, normalized.name, str(normalized.id))
        ttl = ttl_sec if ttl_sec > 0 else 30
        await self._etcd_client.put_with_lease(key, encode_instance(normalized), ttl=ttl)

    async def unregister(self, instance: ServiceInstance) -> None:
        service_bucket = self._services.get(instance.name)
        if not service_bucket:
            return
        service_bucket.pop(instance.id, None)
        if not service_bucket:
            self._services.pop(instance.name, None)
        self._revision += 1

        if self._etcd_client is None:
            return
        key = build_service_key(self._etcd_client.namespace, instance.name, str(instance.id))
        with contextlib.suppress(Exception):
            await self._etcd_client.delete(key)

    async def get_service_instances(
        self, service_name: str
    ) -> list[ServiceInstance]:
        if self._etcd_client is not None:
            prefix = build_prefix(self._etcd_client.namespace, service_name)
            with contextlib.suppress(Exception):
                items = await self._etcd_client.get_prefix(prefix)
                instances: list[ServiceInstance] = []
                for _, value in items:
                    with contextlib.suppress(Exception):
                        inst = decode_instance(value)
                        instances.append(inst)
                        self._services.setdefault(service_name, {})[inst.id] = inst
                if instances:
                    self._revision += 1
                    return instances

        service_bucket = self._services.get(service_name, {})
        return list(service_bucket.values())

    async def get_service_snapshot(
        self, service_name: str
    ) -> ServiceSnapshot | None:
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

        now = time()
        live_instances = [
            inst for inst in instances if inst.heartbeat_at <= 0 or now - inst.heartbeat_at <= 30
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
