from abc import ABC, abstractmethod
from uuid import UUID

from src.models.common.entities import UserEntity


class IUserEntityManager(ABC):
    """用户实体写入接口。"""

    @abstractmethod
    async def insert(self, user_entity: UserEntity) -> UUID:
        """插入新的用户实体并返回实体 ID。"""
        raise NotImplementedError