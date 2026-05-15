from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from src.models.sys.config import RuntimeLogConfig


class RuntimeEventLogger:
    """轻量运行日志器：用于边缘端关键流程节点终端打印。"""

    def __init__(self, config: RuntimeLogConfig | None = None) -> None:
        cfg = config or RuntimeLogConfig()
        self._enabled = bool(cfg.enabled)
        self._include_timestamp = bool(cfg.include_timestamp)
        self._stages = {
            str(stage).strip().lower() for stage in (cfg.stages or []) if str(stage).strip()
        }

    @property
    def enabled(self) -> bool:
        return self._enabled

    def _allow_stage(self, stage: str) -> bool:
        if not self._enabled:
            return False
        if not self._stages:
            return True
        key = stage.strip().lower()
        return "all" in self._stages or key in self._stages

    @staticmethod
    def _format_value(value: Any) -> str:
        if isinstance(value, float):
            return f"{value:.3f}"
        if isinstance(value, (dict, list, tuple)):
            return json.dumps(value, ensure_ascii=False)
        return str(value)

    @staticmethod
    def _print_line(text: str) -> None:
        print(text, flush=True)

    def emit_separator(self) -> None:
        if not self._enabled:
            return

        self._print_line("=" * 70)

    def emit(
        self,
        stage: str,
        event: str,
        details: dict[str, Any] | None = None,
    ) -> None:
        if not self._allow_stage(stage):
            return

        parts = ["[edge]"]
        if self._include_timestamp:
            parts.append(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        parts.append(f"[{stage.strip().lower()}]")
        parts.append(event.strip())

        if details:
            for key, value in details.items():
                parts.append(f"{key}={self._format_value(value)}")

        self._print_line(" ".join(parts))
