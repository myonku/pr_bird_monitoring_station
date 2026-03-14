from typing import Literal

from msgspec import Struct

EntityType = Literal["user", "service", "device", "unknown"]
RateLimitSubjectType = Literal["ip", "entity", "session", "token", "client", "gateway", "route", "composite"]
RateLimitScope = Literal["edge_inbound", "internal_grpc", "auth"]
RateLimitAlgorithm = Literal["fixed_window", "sliding_window", "token_bucket"]


class RateLimitDescriptor(Struct, kw_only=True):
    """描述一个限流事件的上下文信息，用于匹配和决策。"""

    scope: str
    transport: str

    module: str
    action: str
    route: str
    method: str

    authenticated: bool = False

    source_ip: str = ""
    gateway_id: str = ""
    client_id: str = ""

    source_service: str = ""
    target_service: str = ""

    entity_type: EntityType = "unknown"
    entity_id: str = ""
    principal_id: str = ""
    session_id: str = ""
    token_id: str = ""
    token_type: str = ""

    scopes: list[str] = []
    tags: dict[str, str] = {}

    def subject_value(self, subject_type: str) -> str:
        if subject_type == "ip":
            return self.source_ip
        if subject_type == "entity":
            return self.principal_id or self.entity_id
        if subject_type == "session":
            return self.session_id
        if subject_type == "token":
            return self.token_id
        if subject_type == "client":
            return self.client_id
        if subject_type == "gateway":
            return self.gateway_id
        if subject_type == "route":
            return self.route
        return ""


class RateLimitRule(Struct, kw_only=True):
    """描述一个限流规则的条件和限制参数。"""

    id: str
    scope: RateLimitScope
    subject: RateLimitSubjectType
    algorithm: RateLimitAlgorithm
    priority: int = 0
    enabled: bool = True

    limit: int = 0
    burst: int = 0
    window_sec: int = 0

    require_authenticated: bool = False

    match_module: str = ""
    match_action: str = ""
    match_route: str = ""
    match_methods: list[str] = []
    match_entity_types: list[EntityType] = []
    match_token_types: list[str] = []
    match_scopes: list[str] = []
    match_gateway_ids: list[str] = []
    match_source_services: list[str] = []
    match_target_services: list[str] = []
    match_tags: dict[str, str] = {}


class RateLimitBucketKey(Struct, frozen=True):
    """表示一个限流桶的唯一标识，由规则ID和主体值组成。"""

    rule_id: str
    scope: RateLimitScope
    subject_type: RateLimitSubjectType
    subject_value: str
    module: str
    action: str


class RateLimitCounter(Struct):
    """表示一个限流桶的计数器，用于跟踪请求次数和窗口状态。"""

    key: RateLimitBucketKey
    hits: int = 0
    remaining: int = 0
    window_started_at: float = 0.0
    window_reset_at: float = 0.0
    last_seen_at: float = 0.0
    expires_at: float = 0.0


class RateLimitDecision(Struct):
    """表示一个限流决策的结果，包括是否允许请求、违反的规则ID、重试时间等信息。"""

    allowed: bool
    violated_rule_id: str = ""
    retry_after_sec: int = 0
    remaining: int = 0
    subject_key: str = ""
    reason: str = ""
