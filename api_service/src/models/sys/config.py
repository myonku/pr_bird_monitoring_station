from __future__ import annotations

from typing import Literal
from urllib.parse import quote_plus, urlencode
from msgspec import Struct

from src.models.auth.internal_header_keys import HEADER_INTERNAL_ASSERTION


class ProjectConfig(Struct):
    """项目配置模型"""

    redis: RedisConfig | None = None
    mysql: MySQLConfig | None = None
    kafka: KafkaConfig | None = None
    mongo: MongoConfig | None = None
    etcd: EtcdConfig | None = None
    internal_assertion: InternalAssertionConfig | None = None
    secret_key: SecretKeyConfig | None = None


class SecretKeyConfig(Struct, kw_only=True):
    """本地密钥装载配置。"""

    enabled: bool = False
    secret_dir: str = "secret_keys"
    active_key_id: str = ""

    owner_type: str = "service"
    entity_type: str = "service"
    entity_id: str = ""
    entity_name: str = ""
    service_id: str = ""
    service_name: str = ""
    instance_id: str = ""
    instance_name: str = ""

    key_exchange_algorithm: str = "ecdhe_p256"
    signature_algorithm: str = ""

    public_key_ref: str = ""
    private_key_ref: str = ""

    def normalized(self, default_entity_id: str = "") -> "SecretKeyConfig":
        secret_dir = self.secret_dir.strip() or "secret_keys"
        active_key_id = self.active_key_id.strip()

        owner_type = self.owner_type.strip().lower() or "service"
        entity_type = self.entity_type.strip().lower() or "service"
        entity_id = self.entity_id.strip() or default_entity_id
        entity_name = self.entity_name.strip() or entity_id

        service_id = self.service_id.strip() or entity_id
        service_name = self.service_name.strip() or entity_name

        key_exchange_algorithm = (
            self.key_exchange_algorithm.strip().lower() or "ecdhe_p256"
        )
        signature_algorithm = self.signature_algorithm.strip().lower()

        return SecretKeyConfig(
            enabled=self.enabled,
            secret_dir=secret_dir,
            active_key_id=active_key_id,
            owner_type=owner_type,
            entity_type=entity_type,
            entity_id=entity_id,
            entity_name=entity_name,
            service_id=service_id,
            service_name=service_name,
            instance_id=self.instance_id.strip(),
            instance_name=self.instance_name.strip(),
            key_exchange_algorithm=key_exchange_algorithm,
            signature_algorithm=signature_algorithm,
            public_key_ref=self.public_key_ref.strip(),
            private_key_ref=self.private_key_ref.strip(),
        )


class InternalAssertionConfig(Struct, kw_only=True):
    """内部断言验签配置。"""

    enabled: bool = False
    required: bool = False
    header_name: str = HEADER_INTERNAL_ASSERTION

    clock_skew_sec: int = 30
    replay_ttl_sec: int = 15

    enforce_path_binding: bool = False

    def normalized(self) -> "InternalAssertionConfig":
        header_name = self.header_name.strip().lower() if self.header_name else ""
        if not header_name:
            header_name = HEADER_INTERNAL_ASSERTION

        clock_skew_sec = self.clock_skew_sec if self.clock_skew_sec > 0 else 30
        replay_ttl_sec = self.replay_ttl_sec if self.replay_ttl_sec > 0 else 15

        return InternalAssertionConfig(
            enabled=self.enabled,
            required=self.required,
            header_name=header_name,
            clock_skew_sec=clock_skew_sec,
            replay_ttl_sec=replay_ttl_sec,
            enforce_path_binding=self.enforce_path_binding,
        )


class EtcdConfig(Struct, kw_only=True):
    """Etcd 配置模型"""

    HOSTS: list[str]
    USERNAME: str | None = None
    PASSWORD: str | None = None
    TLS_ENABLED: bool = False
    CA_CERT: str | None = None
    CERT_FILE: str | None = None
    KEY_FILE: str | None = None
    NAMESPACE: str = "/bms"
    CIRCUITBREAKER: CircuitBreakerConfig | None = None


class RedisConfig(Struct, kw_only=True):
    """Redis配置模型"""

    # 支持单节点或集群
    MODE: Literal["single", "cluster", "sentinel"] = "single"

    # 单节点兼容字段
    DIALECT: str | None = "redis"
    HOST: str | None = None
    PORT: int | None = None
    PASSWORD: str | None = None
    DATABASE: int = 0

    # 集群/哨兵支持：HOSTS 列表（host:port 格式或仅 host，若仅 host 需与 PORT 一起使用）
    HOSTS: list[str] | None = None
    CIRCUITBREAKER: CircuitBreakerConfig | None = None

    def redis_uris(self) -> list[str]:
        """返回用于连接的 redis URI 列表（单节点返回一个，集群返回多个）。"""
        if self.HOSTS:
            uris = []
            for h in self.HOSTS:
                # 如果 host 已经包含端口则直接使用，否则使用 PORT
                if ":" in h:
                    hostpart = h
                elif self.PORT is not None:
                    hostpart = f"{h}:{self.PORT}"
                else:
                    hostpart = h
                pwd = f":{self.PASSWORD}" if self.PASSWORD else ""
                uris.append(
                    f"{self.DIALECT}://{pwd}@{hostpart}/{self.DATABASE}"
                    if pwd
                    else f"{self.DIALECT}://{hostpart}/{self.DATABASE}"
                )
            return uris

        # 回退到单节点
        if self.HOST and self.PORT is not None:
            pwd = f":{self.PASSWORD}" if self.PASSWORD else ""
            return [
                (
                    f"{self.DIALECT}://{pwd}@{self.HOST}:{self.PORT}/{self.DATABASE}"
                    if pwd
                    else f"{self.DIALECT}://{self.HOST}:{self.PORT}/{self.DATABASE}"
                )
            ]
        return []

    @property
    def redis_uri(self) -> str | None:
        """返回用于单一连接（首 URI 或 None）。"""
        uris = self.redis_uris()
        return uris[0] if uris else None


class MySQLConfig(Struct, kw_only=True):
    """MySQL 配置模型（支持单节点或多主/集群形式的 HOSTS）"""

    DIALECT: str | None = "mysql"
    USER: str | None = None
    PASSWORD: str | None = None
    PORT: int | None = 3306
    HOST: str | None = None
    # 支持 host 或 host:port 列表，用于集群部署
    HOSTS: list[str] | None = None
    DATABASE: str | None = None
    CIRCUITBREAKER: CircuitBreakerConfig | None = None

    def _format_conn(self, hostpart: str) -> str:
        """根据 hostpart（可能包含端口）生成与旧格式兼容的连接字符串。"""
        if ":" in hostpart:
            host, port = hostpart.split(":", 1)
        else:
            host, port = hostpart, str(self.PORT) if self.PORT is not None else ""
        user = self.USER or ""
        pwd = self.PASSWORD or ""
        db = self.DATABASE or ""
        return f"Server={host};Database={db};User Id={user};Password={pwd};Port={port}"

    def mysql_uris(self) -> list[str]:
        """返回用于连接的 MySQL 连接字符串列表（单节点返回一个，集群返回多个）。"""
        if self.HOSTS:
            return [self._format_conn(h) for h in self.HOSTS]

        if self.HOST:
            hostpart = (
                f"{self.HOST}:{self.PORT}" if self.PORT is not None else self.HOST
            )
            return [self._format_conn(hostpart)]

        return []

    @property
    def mysql_uri(self) -> str | None:
        """返回首个可用的 MySQL 连接字符串（若无则返回 None）。"""
        uris = self.mysql_uris()
        return uris[0] if uris else None


class KafkaConfig(Struct, kw_only=True):
    """Kafka 配置模型"""

    BOOTSTRAP_SERVERS: list[str]
    CLIENT_ID: str | None = None
    SECURITY_PROTOCOL: str | None = None  # e.g. PLAINTEXT, SASL_SSL
    SASL_MECHANISM: str | None = None
    SASL_USERNAME: str | None = None
    SASL_PASSWORD: str | None = None
    TOPIC_PREFIX: str | None = None


class MongoConfig(Struct, kw_only=True):
    """MongoDB连接配置"""

    DIALECT: str | None = "mongodb"
    USER: str | None = None
    PORT: int | None = None
    PASSWORD: str | None = None
    HOST: str | None = None
    # 支持 host 或 host:port 列表，用于副本集/分片（SRV 模式仅需域名，不带端口）
    HOSTS: list[str] | None = None
    DATABASE: str
    DIRECTCONNECTION: bool | None = None
    AUTHSOURCE: str | None = None
    REPLICA_SET: str | None = None
    TLS: bool | None = None
    OPTIONS: dict[str, str] | None = None
    CIRCUITBREAKER: CircuitBreakerConfig | None = None

    def _host_part(self, host: str) -> str:
        if (self.DIALECT or "mongodb") == "mongodb+srv":
            return host
        if ":" in host:
            return host
        if self.PORT is not None:
            return f"{host}:{self.PORT}"
        return host

    def mongo_uris(self) -> list[str]:
        """返回用于连接的 MongoDB URI 列表（通常为单个 URI）。

        - 副本集：多个 HOSTS 逗号分隔。
        - 分片集群：连接 mongos，HOSTS 可为多个 mongos 地址或使用 mongodb+srv。
        - 单机：使用 HOST(+PORT)。
        """
        # hosts 片段
        if self.HOSTS:
            hosts_part = ",".join(self._host_part(h) for h in self.HOSTS)
        elif self.HOST:
            hosts_part = self._host_part(self.HOST)
        else:
            return []

        # 用户信息
        userinfo = ""
        if self.USER:
            if self.PASSWORD:
                userinfo = f"{quote_plus(self.USER)}:{quote_plus(self.PASSWORD)}@"
            else:
                userinfo = f"{quote_plus(self.USER)}@"

        # Query 参数
        params: dict[str, str] = {}
        if self.AUTHSOURCE:
            params["authSource"] = self.AUTHSOURCE
        if self.REPLICA_SET:
            params["replicaSet"] = self.REPLICA_SET
        if self.DIRECTCONNECTION is not None:
            params["directConnection"] = "true" if self.DIRECTCONNECTION else "false"
        if self.TLS:
            params["tls"] = "true"
        if self.OPTIONS:
            for k, v in self.OPTIONS.items():
                params[k] = str(v)

        query = "?" + urlencode(params) if params else ""
        db = self.DATABASE or ""
        dialect = self.DIALECT or "mongodb"

        uri = f"{dialect}://{userinfo}{hosts_part}/{db}{query}"
        return [uri]

    @property
    def mongo_uri(self) -> str | None:
        uris = self.mongo_uris()
        return uris[0] if uris else None


class CircuitBreakerConfig(Struct, kw_only=True):
    """熔断器配置

    - failure_threshold: 连续失败多少次后打开熔断
    - recovery_timeout: 进入 OPEN 后多长时间允许半开探测（秒）
    - half_open_max_calls: HALF_OPEN 状态下允许并发的探测调用数
    """

    failure_threshold: int = 5
    recovery_timeout: float = 10.0
    half_open_max_calls: int = 1
