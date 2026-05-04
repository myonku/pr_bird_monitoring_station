from typing import Literal
from uuid import UUID

from msgspec import Struct, field

UserRole = Literal["admin", "user"]
DeviceStatus = Literal["online", "offline", "error", "unknown"]


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
