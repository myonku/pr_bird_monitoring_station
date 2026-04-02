import json
from datetime import datetime
from pathlib import Path
from typing import Any


class RunLogger:
    """为一次实验运行创建独立日志目录并写入结构化 JSON。"""

    def __init__(self, logs_root: Path) -> None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        self.logs_root = logs_root
        self.run_id = timestamp
        self.run_dir = logs_root / self.run_id

    def _ensure_run_dir(self) -> None:
        self.run_dir.mkdir(parents=True, exist_ok=True)

    def save(self, filename: str, payload: dict[str, Any]) -> Path:
        self._ensure_run_dir()
        target = self.run_dir / filename
        target.write_text(
            json.dumps(payload, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        return target

    def find_previous_summary(self) -> Path | None:
        candidates: list[tuple[str, Path]] = []
        if not self.logs_root.exists():
            return None

        for item in self.logs_root.iterdir():
            if not item.is_dir():
                continue
            if item == self.run_dir:
                continue

            summary = item / "summary.json"
            if summary.exists():
                candidates.append((item.name, summary))

        if not candidates:
            return None

        candidates.sort(key=lambda x: x[0])
        return candidates[-1][1]

    def append_timeline(self, filename: str, payload: dict[str, Any]) -> Path:
        target = self.logs_root / filename
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("a", encoding="utf-8") as file:
            file.write(json.dumps(payload, ensure_ascii=False) + "\n")
        return target
