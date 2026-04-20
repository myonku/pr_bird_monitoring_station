from __future__ import annotations

from dataclasses import dataclass
from collections.abc import Sequence
from math import ceil, floor
from threading import Lock
import time
from collections.abc import Callable

from src.iface.authcontrol.auth_control import (
    Build,
    InboundControlRequest,
    InboundControlResult,
    IInboundAuthControl,
)
from src.models.auth.ratelimit import RateLimitDecision, RateLimitDescriptor
from src.models.sys.config import AuthControlConfig


DEFAULT_AUTH_CONTROL_MODULE = "data_worker"


@dataclass(slots=True)
class _FixedWindowState:
    window_started_at: float
    window_reset_at: float
    hits: int = 0


@dataclass(slots=True)
class _TokenBucketState:
    tokens: float
    last_refill_at: float
    last_seen_at: float
    capacity: float
    refill_per_sec: float


class InboundAuthControlService(IInboundAuthControl):
    """data_worker 的本地入站限流门面。"""

    def __init__(
        self,
        cfg: AuthControlConfig | None = None,
        *,
        now: Callable[[], float] | None = None,
    ) -> None:
        self._cfg = (cfg or AuthControlConfig()).normalized(DEFAULT_AUTH_CONTROL_MODULE)
        self._now = now or time.time
        self._lock = Lock()
        self._fixed_windows: dict[str, _FixedWindowState] = {}
        self._token_buckets: dict[str, _TokenBucketState] = {}

    async def enforce_inbound(self, req: InboundControlRequest) -> InboundControlResult:
        if req is None or req.rate_limit_input is None:
            raise ValueError("inbound rate limit input is nil")

        descriptor = Build(req.rate_limit_input)
        decision = self._decide(self._now(), descriptor)
        return InboundControlResult(rate_limit_decision=decision)

    def _decide(
        self,
        now: float,
        descriptor: RateLimitDescriptor | None,
    ) -> RateLimitDecision:
        if descriptor is None:
            return RateLimitDecision(
                allowed=False,
                violated_rule_id="",
                retry_after_sec=0,
                remaining=0,
                subject_key="",
                reason="rate limit descriptor is nil",
            )

        if not self._cfg.enabled:
            return RateLimitDecision(
                allowed=True,
                violated_rule_id="",
                retry_after_sec=0,
                remaining=-1,
                subject_key=_build_subject_key(descriptor, self._cfg.subject),
                reason="auth control disabled",
            )

        rule = self._cfg
        if not _rule_matches_config(rule, descriptor):
            return RateLimitDecision(
                allowed=True,
                violated_rule_id="",
                retry_after_sec=0,
                remaining=-1,
                subject_key=_build_subject_key(descriptor, self._cfg.subject),
                reason="no matching local auth control rule",
            )

        subject_key = _build_subject_key(descriptor, rule.subject)
        if subject_key == "":
            subject_key = _build_composite_subject_key(descriptor)
        if subject_key == "":
            subject_key = "anonymous"

        match rule.algorithm:
            case "token_bucket":
                return self._decide_token_bucket(now, rule, descriptor, subject_key)
            case "sliding_window":
                return self._decide_fixed_window(now, rule, descriptor, subject_key)
            case _:
                return self._decide_fixed_window(now, rule, descriptor, subject_key)

    def _decide_fixed_window(
        self,
        now: float,
        rule: AuthControlConfig,
        descriptor: RateLimitDescriptor,
        subject_key: str,
    ) -> RateLimitDecision:
        window_sec = rule.window_sec if rule.window_sec > 0 else 60
        limit = rule.limit if rule.limit > 0 else 600

        key = _bucket_key_string(rule.rule_id, descriptor, subject_key)

        with self._lock:
            state = self._fixed_windows.get(key)
            if state is None or now >= state.window_reset_at:
                state = _FixedWindowState(
                    window_started_at=now,
                    window_reset_at=now + window_sec,
                    hits=0,
                )
                self._fixed_windows[key] = state
            state.hits += 1
            hits = state.hits
            window_reset_at = state.window_reset_at

        remaining = limit - hits
        if remaining < 0:
            remaining = 0

        if hits > limit:
            retry_after = int(ceil(window_reset_at - now))
            if retry_after < 1:
                retry_after = 1
            return RateLimitDecision(
                allowed=False,
                violated_rule_id=rule.rule_id,
                retry_after_sec=retry_after,
                remaining=0,
                subject_key=subject_key,
                reason=f"rate limited by local rule {rule.rule_id}",
            )

        return RateLimitDecision(
            allowed=True,
            violated_rule_id="",
            retry_after_sec=0,
            remaining=remaining,
            subject_key=subject_key,
            reason="allowed",
        )

    def _decide_token_bucket(
        self,
        now: float,
        rule: AuthControlConfig,
        descriptor: RateLimitDescriptor,
        subject_key: str,
    ) -> RateLimitDecision:
        window_sec = rule.window_sec if rule.window_sec > 0 else 60
        limit = rule.limit if rule.limit > 0 else 600
        burst = rule.burst if rule.burst >= 0 else 0

        capacity = float(limit + burst)
        if capacity <= 0:
            capacity = float(limit)
        if capacity <= 0:
            capacity = 600.0

        refill_per_sec = float(limit) / float(window_sec)
        if refill_per_sec <= 0:
            refill_per_sec = 1.0

        key = _bucket_key_string(rule.rule_id, descriptor, subject_key)

        with self._lock:
            state = self._token_buckets.get(key)
            if state is None:
                state = _TokenBucketState(
                    tokens=capacity,
                    last_refill_at=now,
                    last_seen_at=now,
                    capacity=capacity,
                    refill_per_sec=refill_per_sec,
                )
                self._token_buckets[key] = state

            elapsed = now - state.last_refill_at
            if elapsed > 0:
                state.tokens = min(state.capacity, state.tokens + elapsed * state.refill_per_sec)
                state.last_refill_at = now
            state.last_seen_at = now
            state.capacity = capacity
            state.refill_per_sec = refill_per_sec

            if state.tokens >= 1:
                state.tokens -= 1
                remaining = int(floor(state.tokens))
                if remaining < 0:
                    remaining = 0
                return RateLimitDecision(
                    allowed=True,
                    violated_rule_id="",
                    retry_after_sec=0,
                    remaining=remaining,
                    subject_key=subject_key,
                    reason="allowed",
                )

            missing = 1 - state.tokens
            retry_after = int(ceil(missing / state.refill_per_sec))
            if retry_after < 1:
                retry_after = 1
            state.tokens = max(0.0, state.tokens)

        return RateLimitDecision(
            allowed=False,
            violated_rule_id=rule.rule_id,
            retry_after_sec=retry_after,
            remaining=0,
            subject_key=subject_key,
            reason=f"rate limited by local rule {rule.rule_id}",
        )


def NewInboundAuthControlService(cfg: AuthControlConfig | None = None) -> IInboundAuthControl:
    return InboundAuthControlService(cfg)


def _rule_matches_config(rule: AuthControlConfig, descriptor: RateLimitDescriptor) -> bool:
    if descriptor.scope != rule.scope:
        return False
    if rule.match_module and descriptor.module.strip().lower() != rule.match_module.lower():
        return False
    if rule.match_action and descriptor.action.strip().lower() != rule.match_action.lower():
        return False
    if rule.match_route and descriptor.route.strip() != rule.match_route:
        return False
    if rule.match_methods and not _string_list_contains_fold(rule.match_methods, descriptor.method):
        return False
    if rule.require_authenticated and not descriptor.authenticated:
        return False
    if rule.match_entity_types and not _entity_type_in_list(rule.match_entity_types, descriptor.entity_type):
        return False
    if rule.match_token_types and not _token_type_in_list(rule.match_token_types, descriptor.token_type):
        return False
    if rule.match_gateway_ids and not _string_list_contains_fold(rule.match_gateway_ids, descriptor.gateway_id):
        return False
    if rule.match_source_services and not _string_list_contains_fold(rule.match_source_services, descriptor.source_service):
        return False
    if rule.match_target_services and not _string_list_contains_fold(rule.match_target_services, descriptor.target_service):
        return False
    if rule.match_scopes and not _string_list_contains_all_fold(descriptor.scopes, rule.match_scopes):
        return False
    if rule.match_tags and not _tag_map_matches(descriptor.tags, rule.match_tags):
        return False
    return True


def _build_subject_key(descriptor: RateLimitDescriptor, subject: str) -> str:
    if subject == "composite":
        return _build_composite_subject_key(descriptor)

    value = descriptor.subject_value(subject)
    if value:
        return value.strip()
    return _build_composite_subject_key(descriptor)


def _build_composite_subject_key(descriptor: RateLimitDescriptor) -> str:
    parts = [
        f"scope={str(descriptor.scope).strip()}",
        f"module={descriptor.module.strip()}",
        f"action={descriptor.action.strip()}",
        f"route={descriptor.route.strip()}",
        f"method={descriptor.method.strip()}",
        f"source_ip={descriptor.source_ip.strip()}",
        f"gateway_id={descriptor.gateway_id.strip()}",
        f"client_id={descriptor.client_id.strip()}",
        f"source_service={descriptor.source_service.strip()}",
        f"target_service={descriptor.target_service.strip()}",
        f"entity_type={str(descriptor.entity_type).strip()}",
        f"entity_id={descriptor.entity_id.strip()}",
        f"principal_id={descriptor.principal_id.strip()}",
        f"session_id={descriptor.session_id.strip()}",
        f"token_id={descriptor.token_id.strip()}",
    ]
    filtered = [item for item in parts if not item.endswith("=")]
    if not filtered:
        return ""
    return "|".join(filtered)


def _bucket_key_string(rule_id: str, descriptor: RateLimitDescriptor, subject_key: str) -> str:
    return "|".join(
        [
            rule_id.strip(),
            str(descriptor.scope).strip(),
            descriptor.module.strip(),
            descriptor.action.strip(),
            subject_key.strip(),
        ]
    )


def _string_list_contains_fold(items: list[str], value: str) -> bool:
    needle = value.strip()
    if needle == "":
        return False
    for item in items:
        if item.strip().lower() == needle.lower():
            return True
    return False


def _string_list_contains_all_fold(haystack: list[str], needles: list[str]) -> bool:
    if not needles:
        return True
    for needle in needles:
        if not _string_list_contains_fold(haystack, needle):
            return False
    return True


def _entity_type_in_list(items: Sequence[object], value: str) -> bool:
    needle = value.strip().lower()
    if needle == "":
        return False
    for item in items:
        if str(item).strip().lower() == needle:
            return True
    return False


def _token_type_in_list(items: Sequence[object], value: str) -> bool:
    needle = value.strip().lower()
    if needle == "":
        return False
    for item in items:
        if str(item).strip().lower() == needle:
            return True
    return False


def _tag_map_matches(actual: dict[str, str], expected: dict[str, str]) -> bool:
    if not expected:
        return True
    if not actual:
        return False
    for key, expected_value in expected.items():
        if key not in actual:
            return False
        if actual[key].strip() != expected_value.strip():
            return False
    return True