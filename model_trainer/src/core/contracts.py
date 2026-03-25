from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol


@dataclass(slots=True)
class EvaluationResult:
    leaderboard: list[dict[str, Any]]
    best_lightweight: dict[str, Any] | None
    best_standard: dict[str, Any] | None
    overall_winner: dict[str, Any] | None


class Evaluator(Protocol):
    def evaluate(self, records: list[dict[str, Any]]) -> EvaluationResult:
        """对多模型结果进行统一评估与排序。"""
        ...


class ModelExporter(Protocol):
    def export(self, candidate_id: str, checkpoint_path: Path, output_dir: Path) -> list[Path]:
        """把训练产物转换为边缘端/服务端可部署格式。"""
        ...


class ExperimentPlanner(Protocol):
    def build_plan(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        """根据任务上下文生成候选模型计划。"""
        ...
