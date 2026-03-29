from __future__ import annotations

from pathlib import Path
from typing import Any

from src.config import (
    ModelTier,
    PipelineConfig,
    TaskType,
    build_default_pipeline_config,
    load_pipeline_config,
    load_pipeline_from_settings_toml,
)


def load_or_default_config(path: str | None, settings_path: str) -> PipelineConfig:
    if path:
        return load_pipeline_config(Path(path))

    settings_file = Path(settings_path)
    if settings_file.exists() and settings_file.stat().st_size > 0:
        return load_pipeline_from_settings_toml(settings_file)

    return build_default_pipeline_config()


def filter_pipeline_candidates_by_task_tier(
    pipeline: PipelineConfig,
    task: TaskType,
    tier: ModelTier,
) -> None:
    expected_pairs = {
        (TaskType.DETECTION, ModelTier.LIGHTWEIGHT),
        (TaskType.DETECTION, ModelTier.STANDARD),
        (TaskType.CLASSIFICATION, ModelTier.LIGHTWEIGHT),
        (TaskType.CLASSIFICATION, ModelTier.STANDARD),
    }

    grouped: dict[tuple[TaskType, ModelTier], list[Any]] = {
        key: [] for key in expected_pairs
    }
    for candidate in pipeline.candidates:
        key = (candidate.task, candidate.tier)
        if key not in grouped:
            raise ValueError(
                "Candidate task/tier must be within 4 combinations: "
                "(detection|classification) x (lightweight|standard)."
            )
        grouped[key].append(candidate)

    for pair in expected_pairs:
        items = grouped[pair]
        if len(items) < 1:
            raise ValueError(
                f"Expected at least one candidate for task={pair[0].value}, "
                f"tier={pair[1].value}, got {len(items)}"
            )

    # 同一 task+tier 允许配置多个候选，按配置顺序选择第一个。
    pipeline.candidates = [grouped[(task, tier)][0]]


def rewrite_paths(payload: Any, src_root: Path, dst_root: Path) -> Any:
    src = str(src_root)
    dst = str(dst_root)

    if isinstance(payload, dict):
        return {
            key: rewrite_paths(value, src_root, dst_root)
            for key, value in payload.items()
        }
    if isinstance(payload, list):
        return [rewrite_paths(item, src_root, dst_root) for item in payload]
    if isinstance(payload, str) and payload.startswith(src):
        return dst + payload[len(src) :]
    return payload
