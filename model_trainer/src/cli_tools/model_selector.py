from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from src.config import FrameworkKind, ModelTier, TaskType


@dataclass(slots=True)
class SelectedDetectionModel:
    framework: FrameworkKind
    model_path: Path
    candidate_id: str
    model_name: str
    run_id: str
    score: float
    summary_path: Path


def _score_key_for_task(task: TaskType) -> str:
    if task == TaskType.DETECTION:
        return "map50_95"
    return "top1"


def _model_path_priority(path: Path, framework: FrameworkKind) -> int:
    suffix = path.suffix.lower()
    if framework == FrameworkKind.YOLO:
        if suffix == ".pt":
            return 0
        if suffix == ".onnx":
            return 1
        return 10

    if framework == FrameworkKind.PYTORCH:
        if suffix == ".pth":
            return 0
        if suffix in {".torchscript", ".pt", ".jit"}:
            return 1
        if suffix == ".onnx":
            return 2
        return 10

    return 10


def _load_summary(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _normalize_candidate_paths(record: dict[str, Any]) -> list[Path]:
    raw_paths: list[str] = []
    checkpoint = record.get("checkpoint_path")
    if checkpoint:
        raw_paths.append(str(checkpoint))
    exported = record.get("exported_paths")
    if isinstance(exported, list):
        raw_paths.extend(str(item) for item in exported if item)

    deduped: list[Path] = []
    seen: set[str] = set()
    for raw in raw_paths:
        path = Path(raw).expanduser().resolve()
        key = str(path)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(path)
    return deduped


def _collect_task_records(
    *,
    logs_lane_root: Path,
    task: TaskType,
) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    if not logs_lane_root.exists():
        return records

    score_key = _score_key_for_task(task)

    for summary_path in sorted(logs_lane_root.glob("*/summary.json"), reverse=True):
        try:
            payload = _load_summary(summary_path)
        except Exception:
            continue

        run_id = summary_path.parent.name
        for result in payload.get("results", []):
            if str(result.get("task")) != task.value:
                continue

            score = 0.0
            try:
                score = float(result.get(score_key, 0.0) or 0.0)
            except (TypeError, ValueError):
                score = 0.0

            record = dict(result)
            record["run_id"] = run_id
            record["summary_path"] = str(summary_path)
            record["score"] = score
            records.append(record)

    return records


def select_model_for_task_tier(
    *,
    logs_lane_root: Path,
    task: TaskType,
    tier: ModelTier,
    selection_limit: int,
) -> SelectedDetectionModel:
    if selection_limit < 1:
        raise ValueError("selection_limit must be >= 1")

    records = [
        item
        for item in _collect_task_records(logs_lane_root=logs_lane_root, task=task)
        if str(item.get("tier")) == tier.value
    ]
    if not records:
        raise FileNotFoundError(
            f"No {task.value} training records found for tier={tier.value} under logs: {logs_lane_root}"
        )

    ranked = sorted(
        records,
        key=lambda item: (
            float(item.get("score", 0.0) or 0.0),
            str(item.get("run_id", "")),
        ),
        reverse=True,
    )
    ranked = ranked[:selection_limit]

    for record in ranked:
        try:
            framework = FrameworkKind(str(record.get("framework")))
        except ValueError:
            continue

        paths = sorted(
            _normalize_candidate_paths(record),
            key=lambda path: _model_path_priority(path, framework),
        )
        for path in paths:
            if path.exists() and path.is_file():
                return SelectedDetectionModel(
                    framework=framework,
                    model_path=path,
                    candidate_id=str(record.get("candidate_id", "")),
                    model_name=str(record.get("model_name", "")),
                    run_id=str(record.get("run_id", "")),
                    score=float(record.get("score", 0.0) or 0.0),
                    summary_path=Path(str(record.get("summary_path", ""))),
                )

    raise FileNotFoundError(
        f"{task.value} records were found but no existing model file is available within "
        f"top {selection_limit} candidates. tier={tier.value}, logs={logs_lane_root}"
    )


def select_detection_model_for_tier(
    *,
    logs_lane_root: Path,
    tier: ModelTier,
    selection_limit: int,
) -> SelectedDetectionModel:
    return select_model_for_task_tier(
        logs_lane_root=logs_lane_root,
        task=TaskType.DETECTION,
        tier=tier,
        selection_limit=selection_limit,
    )
