from __future__ import annotations

from uuid import UUID

from src.iface.business.user_profile_svc import IUserProfileManager
from src.models.business.data import UserProfile


class UserProfileManager(IUserProfileManager):
    """用户画像的 Beanie CRUD 管理器。"""

    def __init__(self, document_model: type[UserProfile] = UserProfile) -> None:
        self._document_model = document_model

    async def get_by_id(self, user_id: UUID) -> UserProfile | None:
        if user_id.int == 0:
            raise ValueError("user_id is required")
        return await self._document_model.get(user_id)

    async def get_by_username(self, username: str) -> UserProfile | None:
        return await self._get_first_by_field("username", username)

    async def get_by_email(self, email: str) -> UserProfile | None:
        return await self._get_first_by_field("email", email)

    async def get_by_phone(self, phone: str) -> UserProfile | None:
        return await self._get_first_by_field("phone", phone)

    async def list_all(self) -> list[UserProfile]:
        items = await self._document_model.find_all().to_list()
        items.sort(key=lambda item: str(item.id))
        return items

    async def create(self, user_profile: UserProfile) -> UserProfile:
        if user_profile is None:
            raise ValueError("user profile is required")
        return await user_profile.insert()

    async def update(self, user_profile: UserProfile) -> UserProfile | None:
        if user_profile is None:
            raise ValueError("user profile is required")
        if user_profile.id.int == 0:
            raise ValueError("user_id is required")
        existing = await self._document_model.get(user_profile.id)
        if existing is None:
            return None
        await user_profile.save()
        return user_profile

    async def delete(self, user_id: UUID) -> bool:
        if user_id.int == 0:
            raise ValueError("user_id is required")
        existing = await self._document_model.get(user_id)
        if existing is None:
            return False
        await existing.delete()
        return True

    async def _get_first_by_field(self, field_name: str, value: str) -> UserProfile | None:
        normalized = (value or "").strip()
        if not normalized:
            raise ValueError(f"{field_name} is required")
        items = await self._document_model.find({field_name: normalized}).limit(1).to_list()
        if not items:
            return None
        return items[0]