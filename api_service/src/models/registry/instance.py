from msgspec import Struct, field
from uuid import UUID


class ServiceInstance(Struct, frozen=True):
    """注册到服务发现中的实例信息。"""

    id: UUID
    service_id: str
    name: str
    endpoint: str

    heartbeat: int = 0
    zone: str = ""
    version: str = ""
    weight: int = 1
    tags: list[str] = field(default_factory=list)

    active_comm_key_id: str = ""
    metadata: dict[str, str] = field(default_factory=dict)


class ServiceSnapshot(Struct, frozen=True):
    """某个服务在本地缓存中的快照。"""

    name: str
    instances: list[ServiceInstance]
    revision: int
