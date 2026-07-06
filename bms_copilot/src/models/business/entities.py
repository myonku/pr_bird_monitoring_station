from typing import Literal
from uuid import UUID

from msgspec import Struct, field

UserRole = Literal["admin", "user"]
UserStatus = Literal["active", "inactive", "banned"]
DeviceStatus = Literal["online", "offline", "error", "unknown"]


class UserEntity(Struct, frozen=True):
    """用于认证落库的用户实体信息。"""

    user_entity_id: UUID
    user_profile_id: UUID
    user_name: str
    role: UserRole = "user"
    password_hash: str = ""
    hash_algorithm: str = "bcrypt"
    email: str = ""
    phone: str = ""
    status: UserStatus = "active"
    created_at_ms: int = 0
    updated_at_ms: int = 0
    last_login_at_ms: int = 0
    password_updated_at_ms: int = 0
    metadata: dict[str, str] = field(default_factory=dict)

    @property
    def username(self) -> str:
        return self.user_name


class DeviceEntity(Struct, frozen=True):
    """设备实体信息。"""

    device_entity_id: UUID
    device_name: str = ""
    location_name: str = ""
    latitude: float | None = None
    longitude: float | None = None
    last_heartbeat_ms: int = 0
    status: DeviceStatus = "offline"
    active_comm_key_id: UUID | None = None
    created_at_ms: int = 0
    updated_at_ms: int = 0
    metadata: dict[str, str] = field(default_factory=dict)


class SpeciesProfile(Struct, frozen=True):
    """鸟类固定信息。"""

    species_entity_id: UUID
    scientific_name: str
    label_name: str = ""
    display_name: str = ""
    intro: str = ""
    habitat: str = ""
    protection_level: str = ""
    alias_names: list[str] = field(default_factory=list)
    metadata: dict[str, str] = field(default_factory=dict)
