from abc import ABC, abstractmethod
from uuid import UUID

from src.models.business.data import UserProfile


class IUserProfileManager(ABC):
    """用户画像的 CRUD 管理接口。"""

    @abstractmethod
    async def get_by_id(self, user_id: UUID) -> UserProfile | None:
        """根据用户 ID 获取用户画像。"""
        raise NotImplementedError

    @abstractmethod
    async def get_by_username(self, username: str) -> UserProfile | None:
        """根据用户名获取用户画像。"""
        raise NotImplementedError

    @abstractmethod
    async def get_by_email(self, email: str) -> UserProfile | None:
        """根据邮箱获取用户画像。"""
        raise NotImplementedError

    @abstractmethod
    async def get_by_phone(self, phone: str) -> UserProfile | None:
        """根据手机号获取用户画像。"""
        raise NotImplementedError

    @abstractmethod
    async def list_all(self) -> list[UserProfile]:
        """列出当前所有用户画像。"""
        raise NotImplementedError

    @abstractmethod
    async def create(self, user_profile: UserProfile) -> UserProfile:
        """创建新的用户画像。"""
        raise NotImplementedError

    @abstractmethod
    async def update(self, user_profile: UserProfile) -> UserProfile | None:
        """更新已有用户画像。"""
        raise NotImplementedError

    @abstractmethod
    async def delete(self, user_id: UUID) -> bool:
        """删除用户画像。"""
        raise NotImplementedError
