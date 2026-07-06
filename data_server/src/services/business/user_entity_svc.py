from __future__ import annotations

import json
from datetime import datetime, timezone
from uuid import UUID

from src.iface.business.user_entity_svc import IUserEntityManager
from src.models.business.entities import UserEntity, UserRole, UserStatus
from src.repo.mysql_client import MySQLClient
from src.repo.mysql_dao import EntityUsersDAO


class UserEntityManager(IUserEntityManager):
    """基于 MySQL 的用户实体写入器。"""

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
        if user_entity.user_entity_id.int == 0:
            raise ValueError("user_entity_id is required")
        if user_entity.user_profile_id.int == 0:
            raise ValueError("user_profile_id is required")
        if not user_entity.user_name.strip():
            raise ValueError("user_name is required")
        if not user_entity.password_hash.strip():
            raise ValueError("password_hash is required")

        inserted_id = await self._user_dao.insert_one(
            self._user_to_row(user_entity)
        )
        if inserted_id is None:
            return user_entity.user_entity_id
        return UUID(str(inserted_id))

    @staticmethod
    def _user_to_row(user_entity: UserEntity) -> dict[str, object]:
        now_ms = UserEntityManager._now_ms()
        created_at_ms = (
            user_entity.created_at_ms if user_entity.created_at_ms > 0 else now_ms
        )
        updated_at_ms = (
            user_entity.updated_at_ms if user_entity.updated_at_ms > 0 else now_ms
        )
        password_updated_at_ms = (
            user_entity.password_updated_at_ms
            if user_entity.password_updated_at_ms > 0
            else created_at_ms
        )
        last_login_at_ms = (
            user_entity.last_login_at_ms if user_entity.last_login_at_ms > 0 else 0
        )

        to_user_role = lambda value: value if value in UserRole.__args__ else "user"
        to_user_status = lambda value: value if value in UserStatus.__args__ else "inactive"

        return {
            "user_entity_id": str(user_entity.user_entity_id),
            "user_profile_id": str(user_entity.user_profile_id),
            "user_name": user_entity.user_name.strip(),
            "role": to_user_role(user_entity.role),
            "password_hash": user_entity.password_hash,
            "hash_algorithm": user_entity.hash_algorithm.strip() or "bcrypt",
            "email": user_entity.email.strip(),
            "phone": user_entity.phone.strip(),
            "status": to_user_status(user_entity.status),
            "created_at": UserEntityManager._ms_to_datetime(created_at_ms),
            "updated_at": UserEntityManager._ms_to_datetime(updated_at_ms),
            "last_login_at": (
                None
                if last_login_at_ms <= 0
                else UserEntityManager._ms_to_datetime(last_login_at_ms)
            ),
            "password_updated_at": UserEntityManager._ms_to_datetime(
                password_updated_at_ms
            ),
            "metadata": json.dumps(user_entity.metadata or {}, ensure_ascii=True),
        }

    @staticmethod
    def _ms_to_datetime(ms: int) -> datetime:
        return datetime.fromtimestamp(max(int(ms), 0) / 1000.0, tz=timezone.utc)

    @staticmethod
    def _now_ms() -> int:
        return int(datetime.now(tz=timezone.utc).timestamp() * 1000)
