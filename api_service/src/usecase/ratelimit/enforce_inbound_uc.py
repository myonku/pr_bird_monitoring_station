from collections.abc import Mapping
from dataclasses import dataclass, field
from time import time
from typing import Literal

from src.models.auth.internal_header_keys import (
    HEADER_ACTION,
    HEADER_AUTH_VERIFIED,
    HEADER_CLIENT_ID,
    HEADER_DOWNSTREAM_PRINCIPAL,
    HEADER_DOWNSTREAM_SESSION_ID,
    HEADER_DOWNSTREAM_TOKEN_ID,
    HEADER_FORWARDED_FOR,
    HEADER_GATEWAY_ID,
    HEADER_MODULE,
    HEADER_REAL_IP,
    HEADER_REQUEST_ID,
    HEADER_SCOPES,
    HEADER_SOURCE_SERVICE,
    HEADER_TARGET_SERVICE,
    HEADER_TOKEN_TYPE,
    HEADER_TRACE_ID,
    HEADER_TRUE,
    HEADER_VERIFIED_ENTITY_ID,
    HEADER_VERIFIED_ENTITY_TYPE,
    HEADER_VERIFIED_GATEWAY_ID,
    HEADER_VERIFIED_JTI,
    HEADER_VERIFIED_PRINCIPAL_ID,
    HEADER_VERIFIED_REQUEST_ID,
    HEADER_VERIFIED_SCOPES,
    HEADER_VERIFIED_SESSION_ID,
    HEADER_VERIFIED_SOURCE_SERVICE,
    HEADER_VERIFIED_TARGET_SERVICE,
    HEADER_VERIFIED_TOKEN_ID,
    HEADER_VERIFIED_TRACE_ID,
)
from src.models.auth.ratelimit import RateLimitDecision, RateLimitDescriptor


EntityType = Literal["user", "service", "device"]


@dataclass(slots=True)
class VerifiedRateLimitIdentity:
    """限流链路使用的已验证身份上下文。"""

    authenticated: bool = False
    principal_id: str = ""
    session_id: str = ""
    token_id: str = ""

    gateway_id: str = ""
    source_service: str = ""
    target_service: str = "api_service"

    entity_type: EntityType = "service"
    entity_id: str = "api_service"

    scopes: list[str] = field(default_factory=list)

    trace_id: str = ""
    request_id: str = ""
    assertion_jti: str = ""


class RateLimiterService:
    """限流决策服务骨架（普通服务可复用同一接口语义）。"""

    def __init__(self, limit: int = 200, window_sec: int = 60):
        self.limit = max(limit, 1)
        self.window_sec = max(window_sec, 1)
        self._counter: dict[str, tuple[int, float]] = {}

    async def decide(self, descriptor: RateLimitDescriptor) -> RateLimitDecision:
        now = time()
        key = self._build_counter_key(descriptor)
        hits, reset_at = self._counter.get(key, (0, now + self.window_sec))
        if now >= reset_at:
            hits = 0
            reset_at = now + self.window_sec

        hits += 1
        self._counter[key] = (hits, reset_at)
        remaining = max(self.limit - hits, 0)
        if hits <= self.limit:
            return RateLimitDecision(
                allowed=True,
                violated_rule_id="",
                retry_after_sec=0,
                remaining=remaining,
                subject_key=key,
                reason="",
            )
        return RateLimitDecision(
            allowed=False,
            violated_rule_id="default-fixed-window",
            retry_after_sec=max(int(reset_at - now), 1),
            remaining=0,
            subject_key=key,
            reason="rate limited",
        )

    @staticmethod
    def _build_counter_key(descriptor: RateLimitDescriptor) -> str:
        subject = _select_subject_key(descriptor)
        return (
            f"{descriptor.transport}:{descriptor.route}:{descriptor.method}:{subject}"
        )


class DescriptorFactory:
    """协议上下文到 RateLimitDescriptor 的转换骨架。"""

    def build(
        self,
        transport: str,
        route: str,
        method: str,
        identity: VerifiedRateLimitIdentity,
        headers: Mapping[str, str] | None = None,
    ) -> RateLimitDescriptor:
        header_map = headers or {}

        module = _first_nonempty(header_map, HEADER_MODULE, default="api_service")
        action = _first_nonempty(header_map, HEADER_ACTION, default=method)
        source_ip = _first_nonempty(
            header_map,
            HEADER_FORWARDED_FOR,
            HEADER_REAL_IP,
        )
        client_id = _first_nonempty(header_map, HEADER_CLIENT_ID)
        token_type = _first_nonempty(header_map, HEADER_TOKEN_TYPE)

        return RateLimitDescriptor(
            scope="internal_grpc",
            transport=transport,
            module=module,
            action=action,
            route=route,
            method=method,
            authenticated=identity.authenticated,
            source_ip=source_ip,
            gateway_id=identity.gateway_id,
            client_id=client_id,
            source_service=identity.source_service,
            target_service=identity.target_service,
            entity_type=identity.entity_type,
            entity_id=identity.entity_id,
            principal_id=identity.principal_id,
            session_id=identity.session_id,
            token_id=identity.token_id,
            token_type=token_type,
            scopes=list(identity.scopes),
            tags=_build_trace_tags(identity),
        )


def resolve_verified_identity(headers: Mapping[str, str]) -> VerifiedRateLimitIdentity:
    principal_id = _first_nonempty(
        headers,
        HEADER_VERIFIED_PRINCIPAL_ID,
        HEADER_DOWNSTREAM_PRINCIPAL,
    )
    session_id = _first_nonempty(
        headers,
        HEADER_VERIFIED_SESSION_ID,
        HEADER_DOWNSTREAM_SESSION_ID,
    )
    token_id = _first_nonempty(
        headers,
        HEADER_VERIFIED_TOKEN_ID,
        HEADER_DOWNSTREAM_TOKEN_ID,
    )

    verified_flag = _first_nonempty(headers, HEADER_AUTH_VERIFIED)
    authenticated = verified_flag == HEADER_TRUE or bool(principal_id)

    raw_entity_type = _first_nonempty(
        headers,
        HEADER_VERIFIED_ENTITY_TYPE,
        "x-entity-type",
        default="service",
    )

    scopes_header = _first_nonempty(headers, HEADER_VERIFIED_SCOPES, HEADER_SCOPES)
    return VerifiedRateLimitIdentity(
        authenticated=authenticated,
        principal_id=principal_id,
        session_id=session_id,
        token_id=token_id,
        gateway_id=_first_nonempty(
            headers,
            HEADER_VERIFIED_GATEWAY_ID,
            HEADER_GATEWAY_ID,
        ),
        source_service=_first_nonempty(
            headers,
            HEADER_VERIFIED_SOURCE_SERVICE,
            HEADER_SOURCE_SERVICE,
        ),
        target_service=_first_nonempty(
            headers,
            HEADER_VERIFIED_TARGET_SERVICE,
            HEADER_TARGET_SERVICE,
            default="api_service",
        ),
        entity_type=_normalize_entity_type(raw_entity_type),
        entity_id=_first_nonempty(
            headers,
            HEADER_VERIFIED_ENTITY_ID,
            "x-entity-id",
            default="api_service",
        ),
        scopes=_split_csv(scopes_header),
        trace_id=_first_nonempty(
            headers,
            HEADER_VERIFIED_TRACE_ID,
            HEADER_TRACE_ID,
        ),
        request_id=_first_nonempty(
            headers,
            HEADER_VERIFIED_REQUEST_ID,
            HEADER_REQUEST_ID,
        ),
        assertion_jti=_first_nonempty(headers, HEADER_VERIFIED_JTI),
    )


def _first_nonempty(
    headers: Mapping[str, str],
    *keys: str,
    default: str = "",
) -> str:
    for key in keys:
        if not key:
            continue
        value = headers.get(key, "")
        if value:
            return value
    return default


def _split_csv(raw: str) -> list[str]:
    if not raw:
        return []
    values: list[str] = []
    for item in raw.split(","):
        normalized = item.strip()
        if normalized:
            values.append(normalized)
    return values


def _normalize_entity_type(raw: str) -> EntityType:
    normalized = raw.strip().lower() if raw else ""
    if normalized == "user":
        return "user"
    if normalized == "device":
        return "device"
    return "service"


def _build_trace_tags(identity: VerifiedRateLimitIdentity) -> dict[str, str]:
    tags: dict[str, str] = {}
    if identity.trace_id:
        tags["trace_id"] = identity.trace_id
    if identity.request_id:
        tags["request_id"] = identity.request_id
    if identity.assertion_jti:
        tags["assertion_jti"] = identity.assertion_jti
    return tags


def _select_subject_key(descriptor: RateLimitDescriptor) -> str:
    if descriptor.principal_id:
        return f"principal:{descriptor.principal_id}"
    if descriptor.gateway_id and descriptor.route:
        return f"gateway_route:{descriptor.gateway_id}:{descriptor.route}"
    if descriptor.gateway_id:
        return f"gateway:{descriptor.gateway_id}"
    if descriptor.source_ip:
        return f"ip:{descriptor.source_ip}"
    if descriptor.client_id:
        return f"client:{descriptor.client_id}"
    return "anonymous"


class EnforceInboundUsecase:
    """入站限流编排：Build -> Decide。"""

    def __init__(self, factory: DescriptorFactory, limiter: RateLimiterService):
        self.factory = factory
        self.limiter = limiter

    async def execute(
        self, transport: str, route: str, method: str, headers: dict[str, str]
    ) -> RateLimitDecision:
        identity = resolve_verified_identity(headers)
        descriptor = self.factory.build(
            transport=transport,
            route=route,
            method=method,
            identity=identity,
            headers=headers,
        )
        return await self.limiter.decide(descriptor)
