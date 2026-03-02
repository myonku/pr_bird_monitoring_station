from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path


class RunLogger:
    """用于记录训练过程中的配置、每个 epoch 的指标以及最终的总结信息。"""

    def __init__(
        self, logs_root: Path, model_name: str, run_name: str | None = None
    ) -> None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        suffix = run_name or model_name
        self.run_id = f"{timestamp}_{suffix}"
        self.run_dir = logs_root / self.run_id
        self.run_dir.mkdir(parents=True, exist_ok=True)
        self.metrics_file = self.run_dir / "metrics.jsonl"
        self.summary_file = self.run_dir / "summary.json"
        self.config_file = self.run_dir / "config.json"

    def log_config(self, config: dict) -> None:
        """将训练配置保存为 config.json 文件，便于后续分析和复现。"""
        self.config_file.write_text(
            json.dumps(config, indent=2, ensure_ascii=False), encoding="utf-8"
        )

    def log_epoch(self, record: dict) -> None:
        """将每个 epoch 的指标追加写入 metrics.jsonl 文件，每行一个 JSON 对象。"""
        with self.metrics_file.open("a", encoding="utf-8") as fp:
            fp.write(json.dumps(record, ensure_ascii=False) + "\n")

    def log_summary(self, summary: dict) -> Path:
        """将训练的总结信息保存为 summary.json 文件，包含最佳性能、最终性能等关键信息。"""
        self.summary_file.write_text(
            json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8"
        )
        return self.summary_file
