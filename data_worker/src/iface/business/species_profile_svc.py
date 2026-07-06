from abc import ABC, abstractmethod
from uuid import UUID

from src.models.business.entities import SpeciesProfile


class ISpeciesProfileManager(ABC):
    """鸟类信息的管理接口（MySQL 仓储）。"""

    @abstractmethod
    async def get_by_id(self, species_entity_id: UUID) -> SpeciesProfile | None:
        """按物种实体 ID 查询。"""
        raise NotImplementedError

    @abstractmethod
    async def get_by_scientific_name(self, scientific_name: str) -> SpeciesProfile | None:
        """按学名查询。"""
        raise NotImplementedError

    @abstractmethod
    async def get_by_label_name(self, label_name: str) -> SpeciesProfile | None:
        """按训练标签查询。"""
        raise NotImplementedError

    @abstractmethod
    async def get_by_display_name(self, display_name: str) -> SpeciesProfile | None:
        """按显示名查询。"""
        raise NotImplementedError

    @abstractmethod
    async def list_all(self) -> list[SpeciesProfile]:
        """列出全部鸟类信息。"""
        raise NotImplementedError

    @abstractmethod
    async def create(self, profile: SpeciesProfile) -> UUID:
        """创建鸟类信息，返回实体 ID。"""
        raise NotImplementedError

    @abstractmethod
    async def update(self, profile: SpeciesProfile) -> bool:
        """更新鸟类信息。"""
        raise NotImplementedError

    @abstractmethod
    async def delete(self, species_entity_id: UUID) -> bool:
        """删除鸟类信息。"""
        raise NotImplementedError
