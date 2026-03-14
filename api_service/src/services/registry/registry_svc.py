from src.models.registry.instance import ServiceInstance, ServiceSnapshot


class RegistryService:
    """服务注册与发现快照服务。"""

    def __init__(self):
        ...

    async def register(self, instance: ServiceInstance, ttl_sec: int) -> None:
        ...

    async def unregister(self, instance: ServiceInstance) -> None:
        ...

    async def get_service_instances(self, service_name: str) -> list[ServiceInstance]:
        ...

    async def get_service_snapshot(self, service_name: str) -> ServiceSnapshot | None:
        ...

    async def choose_endpoint(
        self, service_name: str, affinity_key: str = "", require_tags: list[str] | None = None
    ) -> ServiceInstance | None:
        ...
