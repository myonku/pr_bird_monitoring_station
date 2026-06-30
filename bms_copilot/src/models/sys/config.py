from __future__ import annotations

from typing import Literal
from urllib.parse import quote_plus, urlencode
from msgspec import Struct, field

from src.models.auth.auth import TokenType
from src.models.auth.ratelimit import (
    RateLimitAlgorithm,
    RateLimitScope,
    RateLimitSubjectType,
)
from src.models.common.entry_type import EntityType
from src.models.inference.config import InferenceConfig


DEFAULT_COPILOT_GRPC_LISTEN_PORT = 50054
DEFAULT_COPILOT_GRPC_LISTEN_HOST = "127.0.0.1"
RuntimeRunMode = Literal["development", "no_auth"]


class ProjectConfig(Struct):
    """项目配置模型"""

    redis: RedisConfig | None = None
    mysql: MySQLConfig | None = None
    mongo: MongoConfig | None = None
    etcd: EtcdConfig | None = None
    runtime: RuntimeConfig | None = None
    auth: AuthConfig | None = None
    auth_control: AuthControlConfig | None = None
    inference: InferenceConfig | None = None

    def build_secret_key_startup_params(
        self,
        default_entity_id: str = "",
    ) -> SecretKeyStartupParams:
        runtime_cfg = (
            self.runtime.normalized(default_entity_id)
            if self.runtime is not None
            else RuntimeConfig().normalized(default_entity_id)
        )
        auth_cfg = (
            self.auth.normalized()
            if self.auth is not None
            else AuthConfig().normalized()
        )

        return SecretKeyStartupParams(
            secret_key_dir=auth_cfg.secret_key_dir,
            active_key_id=auth_cfg.active_key_id,
            entity_type=runtime_cfg.entity_type,
            entity_id=runtime_cfg.instance_id,
            entity_name=runtime_cfg.service_name,
            instance_id=runtime_cfg.instance_id,
            instance_name=runtime_cfg.service_name,
        )


class AgentConfig(Struct, kw_only=True):
    """Agent 助手模块的提供商和模型配置"""

    provider: str = "openai"
    model: str = "gpt-3.5-turbo"
    max_tokens: int = 2048
    temperature: float = 0.7
    top_p: float = 1.0
    frequency_penalty: float = 0.0
    presence_penalty: float = 0.0
    

class RuntimeConfig(Struct, kw_only=True):
    """服务本体运行时标识配置。"""

    entity_type: str = "service"
    service_name: str = ""
    instance_id: str = ""
    run_mode: RuntimeRunMode = "development"
    grpc_listen_host: str = DEFAULT_COPILOT_GRPC_LISTEN_HOST
    grpc_listen_port: int = DEFAULT_COPILOT_GRPC_LISTEN_PORT

    def normalized(self, default_entity_id: str = "") -> "RuntimeConfig":
        entity_type = self.entity_type.strip().lower() or "service"
        instance_id = self.instance_id.strip() or default_entity_id
        service_name = self.service_name.strip() or instance_id

        return RuntimeConfig(
            entity_type=entity_type,
            service_name=service_name,
            instance_id=instance_id,
            run_mode=normalize_runtime_run_mode(self.run_mode),
            grpc_listen_host=(
                self.grpc_listen_host.strip()
                if isinstance(self.grpc_listen_host, str)
                and self.grpc_listen_host.strip()
                else DEFAULT_COPILOT_GRPC_LISTEN_HOST
            ),
            grpc_listen_port=(
                self.grpc_listen_port
                if isinstance(self.grpc_listen_port, int) and self.grpc_listen_port > 0
                else DEFAULT_COPILOT_GRPC_LISTEN_PORT
            ),
        )


def normalize_runtime_run_mode(raw: object) -> RuntimeRunMode:
    mode = str(raw or "").strip().lower()
    if mode in {"", "development", "dev", "local", "test"}:
        return "development"
    if mode in {"no_auth", "no-auth", "noauth"}:
        return "no_auth"
    raise ValueError(f"unsupported runtime run_mode: {mode}")


class AuthConfig(Struct, kw_only=True):
    """认证相关配置。"""

    secret_key_dir: str = "secret_keys"
    active_key_id: str = ""

    def normalized(self) -> "AuthConfig":
        return AuthConfig(
            secret_key_dir=self.secret_key_dir.strip() or "secret_keys",
            active_key_id=self.active_key_id.strip(),
        )


class AuthControlConfig(Struct, kw_only=True):
    """本地 AuthControl 限流配置。"""

    enabled: bool = True
    rule_id: str = ""
    scope: RateLimitScope = "auth"
    subject: RateLimitSubjectType = "composite"
    algorithm: RateLimitAlgorithm = "fixed_window"

    limit: int = 600
    burst: int = 0
    window_sec: int = 60

    require_authenticated: bool = False

    match_module: str = ""
    match_action: str = ""
    match_route: str = ""
    match_methods: list[str] = field(default_factory=lambda: ["POST"])
    match_entity_types: list[EntityType] = field(default_factory=list)
    match_token_types: list[TokenType] = field(default_factory=list)
    match_gateway_ids: list[str] = field(default_factory=list)
    match_source_services: list[str] = field(default_factory=list)
    match_target_services: list[str] = field(default_factory=list)
    match_scopes: list[str] = field(default_factory=list)
    match_tags: dict[str, str] = field(default_factory=dict)

    def normalized(self, default_module: str) -> "AuthControlConfig":
        normalized = AuthControlConfig(
            enabled=self.enabled,
            rule_id=self.rule_id.strip(),
            scope=normalize_rate_limit_scope(self.scope),
            subject=normalize_rate_limit_subject_type(self.subject),
            algorithm=normalize_rate_limit_algorithm(self.algorithm),
            limit=self.limit,
            burst=self.burst,
            window_sec=self.window_sec,
            require_authenticated=self.require_authenticated,
            match_module=self.match_module.strip(),
            match_action=self.match_action.strip(),
            match_route=self.match_route.strip(),
            match_methods=normalize_string_list(self.match_methods),
            match_entity_types=normalize_entity_type_list(self.match_entity_types),
            match_token_types=normalize_token_type_list(self.match_token_types),
            match_gateway_ids=normalize_string_list(self.match_gateway_ids),
            match_source_services=normalize_string_list(self.match_source_services),
            match_target_services=normalize_string_list(self.match_target_services),
            match_scopes=normalize_string_list(self.match_scopes),
            match_tags=normalize_string_map(self.match_tags),
        )

        if normalized.rule_id == "":
            normalized.rule_id = "local-auth-control"
        if normalized.match_module == "":
            normalized.match_module = default_module.strip()
        if normalized.limit <= 0:
            normalized.limit = 600
        if normalized.burst < 0:
            normalized.burst = 0
        if normalized.window_sec <= 0:
            normalized.window_sec = 60
        if len(normalized.match_methods) == 0:
            normalized.match_methods = ["POST"]
        if normalized.match_tags is None:
            normalized.match_tags = {}
        return normalized


class SecretKeyStartupParams(Struct, kw_only=True):
    """启动期传递给密钥服务的参数快照。"""

    secret_key_dir: str = "secret_keys"
    active_key_id: str = ""

    entity_type: str = "service"
    entity_id: str = ""
    entity_name: str = ""
    instance_id: str = ""
    instance_name: str = ""


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


def normalize_rate_limit_scope(raw: object) -> RateLimitScope:
    scope = str(raw or "").strip().lower()
    if scope in {"", "auth"}:
        return "auth"
    if scope == "edge_inbound":
        return "edge_inbound"
    if scope == "internal_grpc":
        return "internal_grpc"
    return "auth"


def normalize_rate_limit_subject_type(raw: object) -> RateLimitSubjectType:
    subject = str(raw or "").strip().lower()
    if subject in {"", "composite"}:
        return "composite"
    if subject == "ip":
        return "ip"
    if subject == "entity":
        return "entity"
    if subject == "session":
        return "session"
    if subject == "token":
        return "token"
    if subject == "client":
        return "client"
    if subject == "gateway":
        return "gateway"
    if subject == "route":
        return "route"
    return "composite"


def normalize_rate_limit_algorithm(raw: object) -> RateLimitAlgorithm:
    algorithm = str(raw or "").strip().lower()
    if algorithm in {"", "fixed_window"}:
        return "fixed_window"
    if algorithm == "sliding_window":
        return "sliding_window"
    if algorithm == "token_bucket":
        return "token_bucket"
    return "fixed_window"


def normalize_string_list(items: list[str] | None) -> list[str]:
    if not items:
        return []
    output: list[str] = []
    for item in items:
        trimmed = item.strip()
        if trimmed:
            output.append(trimmed)
    return output


def normalize_entity_type_list(items: list[EntityType] | None) -> list[EntityType]:
    if not items:
        return []
    output: list[EntityType] = []
    for item in items:
        normalized = str(item).strip().lower()
        if normalized in {"user", "device", "service"}:
            output.append(normalized)  # type: ignore[arg-type]
    return output


def normalize_token_type_list(items: list[TokenType] | None) -> list[TokenType]:
    if not items:
        return []
    output: list[TokenType] = []
    for item in items:
        normalized = str(item).strip().lower()
        if normalized in {"access", "refresh", "service", "downstream"}:
            output.append(normalized)  # type: ignore[arg-type]
    return output


def normalize_string_map(values: dict[str, str] | None) -> dict[str, str]:
    if not values:
        return {}
    output: dict[str, str] = {}
    for key, value in values.items():
        trimmed_key = key.strip()
        trimmed_value = value.strip()
        if trimmed_key and trimmed_value:
            output[trimmed_key] = trimmed_value
    return output
