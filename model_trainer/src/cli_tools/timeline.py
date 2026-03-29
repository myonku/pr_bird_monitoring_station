from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from src.config import ModelTier, TaskType
from src.models.common import lane_key


def _load_summary(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _score_key_for_task(task: TaskType) -> str:
    return "map50_95" if task == TaskType.DETECTION else "top1"


def _winner_score(winner: dict[str, Any] | None, task: TaskType) -> float | None:
    if not winner:
        return None
    score_key = _score_key_for_task(task)
    try:
        return float(winner.get(score_key, 0.0) or 0.0)
    except (TypeError, ValueError):
        return None


def build_compare_timeline_entry(
    *,
    task: TaskType,
    tier: ModelTier,
    run_id: str,
    previous_summary_path: Path | None,
    current_summary_path: Path,
    comparison_json_path: Path | None,
) -> dict[str, Any]:
    current_summary = _load_summary(current_summary_path)
    current_winner = current_summary.get("comparison", {}).get("overall_winner")

    if previous_summary_path is None:
        return {
            "run_id": run_id,
            "lane": lane_key(task, tier),
            "task": task.value,
            "tier": tier.value,
            "status": "first_run_no_compare",
            "previous_summary": None,
            "current_summary": str(current_summary_path),
            "current_winner": current_winner,
            "current_winner_score": _winner_score(current_winner, task),
            "comparison_summary": None,
        }

    previous_summary = _load_summary(previous_summary_path)
    previous_winner = previous_summary.get("comparison", {}).get("overall_winner")

    previous_score = _winner_score(previous_winner, task)
    current_score = _winner_score(current_winner, task)
    delta = None
    if previous_score is not None and current_score is not None:
        delta = round(current_score - previous_score, 6)

    return {
        "run_id": run_id,
        "lane": lane_key(task, tier),
        "task": task.value,
        "tier": tier.value,
        "status": "compared_with_previous",
        "previous_summary": str(previous_summary_path),
        "current_summary": str(current_summary_path),
        "comparison_summary": (
            str(comparison_json_path) if comparison_json_path else None
        ),
        "previous_winner": previous_winner,
        "current_winner": current_winner,
        "previous_winner_score": previous_score,
        "current_winner_score": current_score,
        "winner_changed": (
            (previous_winner or {}).get("candidate_id")
            != (current_winner or {}).get("candidate_id")
        ),
        "score_delta": delta,
    }
