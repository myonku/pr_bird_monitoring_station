from __future__ import annotations

from dataclasses import dataclass, field
from threading import Lock


@dataclass(slots=True)
class AuthRuntimeMetrics:
    """运行期认证链路的轻量计数指标。"""

    _lock: Lock = field(default_factory=Lock, init=False, repr=False)
    _counters: dict[str, int] = field(default_factory=dict, init=False, repr=False)

    def increment(self, name: str, delta: int = 1) -> None:
        if delta == 0:
            return
        with self._lock:
            self._counters[name] = self._counters.get(name, 0) + delta

    def snapshot(self) -> dict[str, int]:
        with self._lock:
            return dict(self._counters)
