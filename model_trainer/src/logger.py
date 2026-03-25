from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any


class RunLogger:
    """为一次实验运行创建独立日志目录并写入结构化 JSON。"""

    def __init__(self, logs_root: Path, experiment_name: str) -> None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.run_id = f"{timestamp}_{experiment_name}"
        self.run_dir = logs_root / self.run_id
        self.run_dir.mkdir(parents=True, exist_ok=True)

    def save(self, filename: str, payload: dict[str, Any]) -> Path:
        target = self.run_dir / filename
        target.write_text(
            json.dumps(payload, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        return target
