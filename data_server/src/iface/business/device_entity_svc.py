from abc import ABC, abstractmethod
from uuid import UUID

from src.models.common.entities import DeviceEntity


class IDeviceEntityManager(ABC):
    """设备实体的 CRUD 管理接口。"""

    @abstractmethod
    async def get_by_id(self, device_entity_id: UUID) -> DeviceEntity | None:
        """根据设备实体 ID 获取设备。"""
        raise NotImplementedError

    @abstractmethod
    async def list_all(self) -> list[DeviceEntity]:
        """列出全部设备。"""
        raise NotImplementedError

    @abstractmethod
    async def create(self, device_entity: DeviceEntity) -> UUID:
        """创建设备，返回设备实体 ID。"""
        raise NotImplementedError

    @abstractmethod
    async def update(self, device_entity: DeviceEntity) -> bool:
        """更新设备。"""
        raise NotImplementedError

    @abstractmethod
    async def delete(self, device_entity_id: UUID) -> bool:
        """删除设备。"""
        raise NotImplementedError