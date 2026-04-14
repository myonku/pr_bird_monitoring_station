from abc import ABC, abstractmethod

from src.models.common.instance import ServiceInstance, ServiceSnapshot


class IRegistryManager(ABC):
    """服务注册与发现管理接口。"""

    @abstractmethod
    async def register(self, instance: ServiceInstance, ttl_sec: int) -> None:
        """注册服务实例并维持心跳，ttl_sec 是注册过期时间，服务实例需要在过期前续约以保持可用。"""
        raise NotImplementedError

    @abstractmethod
    async def unregister(self, instance: ServiceInstance) -> None:
        """注销服务实例。"""
        raise NotImplementedError

    @abstractmethod
    async def get_service_instances(self, service_name: str) -> list[ServiceInstance]:
        """根据服务名称获取可用实例。"""
        raise NotImplementedError

    @abstractmethod
    async def get_service_snapshot(self, service_name: str) -> ServiceSnapshot | None:
        """根据服务名称获取当前快照。"""
        raise NotImplementedError

    @abstractmethod
    async def choose_endpoint(
        self,
        service_name: str,
        affinity_key: str = "",
        require_tags: list[str] | None = None,
    ) -> ServiceInstance | None:
        """根据服务名称、亲和性键和标签要求选择端点。"""
        raise NotImplementedError

