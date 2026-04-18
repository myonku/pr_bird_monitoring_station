from __future__ import annotations

from uuid import UUID

from src.iface.business.user_entity_svc import IUserEntityManager
from src.models.common.entities import UserEntity
from src.repo.mysql_client import MySQLClient
from src.repo.mysql_dao import EntityUsersDAO


class UserEntityManager(IUserEntityManager):
    """基于 MySQL 的用户实体管理器，仅支持插入。"""

    def __init__(
        self,
        *,
        mysql_client: MySQLClient | None = None,
    ) -> None:
        if mysql_client is None:
            raise ValueError("user entity manager dependencies are required")
        self._user_dao = EntityUsersDAO(mysql_client)

    async def insert(self, user_entity: UserEntity) -> UUID:
        if user_entity is None:
            raise ValueError("user entity is required")

        inserted_id = await self._user_dao.insert_one(self._user_to_row(user_entity))
        if inserted_id is None:
            return user_entity.user_entity_id
        return UUID(str(inserted_id))

    @staticmethod
    def _user_to_row(user_entity: UserEntity) -> dict[str, object]:
        return {
            "user_entity_id": str(user_entity.user_entity_id),
            "username": user_entity.username.strip(),
            "email": user_entity.email.strip(),
            "phone": user_entity.phone.strip(),
            "role": user_entity.role,
            "password_hash": user_entity.password_hash,
            "metadata": user_entity.metadata,
        }