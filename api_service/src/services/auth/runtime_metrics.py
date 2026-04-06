from __future__ import annotations

from dataclasses import dataclass, field
from threading import Lock


@dataclass(slots=True)
class AuthRuntimeMetrics:
    """运行期认证与断言链路的轻量计数指标。"""

    _lock: Lock = field(default_factory=Lock, init=False, repr=False)
    _counters: dict[str, int] = field(default_factory=dict, init=False, repr=False)

    def increment(self, name: str, delta: int = 1) -> None:
        if delta == 0:
            return
        with self._lock:
            self._counters[name] = self._counters.get(name, 0) + delta

    def record_assertion_attempt(self) -> None:
        self.increment("internal_assertion_verify_attempt_total")

    def record_assertion_success(self) -> None:
        self.increment("internal_assertion_verify_success_total")

    def record_assertion_failure(self) -> None:
        self.increment("internal_assertion_verify_failed_total")

    def record_assertion_replay_hit(self) -> None:
        self.increment("internal_assertion_replay_hit_total")

    def snapshot(self) -> dict[str, int]:
        with self._lock:
            return dict(self._counters)
