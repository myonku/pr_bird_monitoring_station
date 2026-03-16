from msgspec import Struct


class ServiceInstance(Struct, frozen=True):
    """注册到服务发现中的实例信息。"""

    id: str
    service_id: str
    name: str
    endpoint: str

    heartbeat_at: float
    zone: str | None
    version: str | None
    weight: int
    tags: list[str]

    active_comm_key_id: str | None
    require_app_encryption: bool = False
    metadata: dict[str, str] = {}


class ServiceSnapshot(Struct, frozen=True):
    """某个服务在本地缓存中的快照。"""

    name: str
    instances: list[ServiceInstance]
    revision: int
