from uuid import UUID

from msgspec import Struct


class ServiceInstance(Struct, frozen=True):
    """
    注册到 etcd 的实例信息（值）
    """

    id: UUID
    name: str
    endpoint: str  # http://host:port 或 grpc://host:port
    service_id: str
    zone: str | None
    version: str | None
    weight: int
    tags: list[str]
    meta_json: str
    heartbeat_at: float
    active_comm_key: str | None


class ServiceSnapshot(Struct, frozen=True):
    """
    从 etcd watch 得到的某服务的快照（缓存到内存，供路由使用）
    """

    name: str
    instances: list[ServiceInstance]
    revision: int
