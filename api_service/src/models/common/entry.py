from typing import Literal
from uuid import UUID

from msgspec import Struct

EntityType = Literal["user", "service", "device"]
UserRole = Literal["admin", "user"]
DeviceStatus = Literal["active", "disabled", "blocked", "invoked"]


class User(Struct, frozen=True):
    """认证用户实体。"""

    id: UUID
    account_id: str
    user_name: str
    password_hash: str
    role: UserRole


class EdgeDevice(Struct, frozen=True):
    """边缘设备实体。"""

    id: UUID
    name: str
    device_secret_hash: str
    zone: str
    status: DeviceStatus
    last_online: int


class ServiceEntry(Struct, frozen=True):
    """服务实体定义。"""

    id: UUID
    name: str
    service_secret_hash: str
    active_comm_key_id: str
    key_entity_type: str
