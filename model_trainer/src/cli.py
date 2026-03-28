from __future__ import annotations

import argparse
import json
import shutil
from pathlib import Path
from typing import Any

from src.config import (
    FrameworkKind,
    ModelTier,
    PipelineConfig,
    TaskType,
    build_default_pipeline_config,
    load_pipeline_from_settings_toml,
    load_pipeline_config,
)
from src.cropper.dataset_cropper import DatasetCropper, build_cropper_backend
from src.datasets.datasets import build_dataset_adapter, resolve_dataset_root
from src.evaluator.comparator import compare_summary_files, save_comparison
from src.engine import run_experiment
from src.models.common import lane_key
from src.logger import RunLogger


def _load_or_default_config(path: str | None, settings_path: str) -> PipelineConfig:
    if path:
        return load_pipeline_config(Path(path))

    settings_file = Path(settings_path)
    if settings_file.exists() and settings_file.stat().st_size > 0:
        return load_pipeline_from_settings_toml(settings_file)

    return build_default_pipeline_config()


def _filter_pipeline_candidates_by_task_tier(
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


def _build_compare_timeline_entry(
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
        "comparison_summary": str(comparison_json_path) if comparison_json_path else None,
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


def _rewrite_paths(payload: Any, src_root: Path, dst_root: Path) -> Any:
    src = str(src_root)
    dst = str(dst_root)

    if isinstance(payload, dict):
        return {key: _rewrite_paths(value, src_root, dst_root) for key, value in payload.items()}
    if isinstance(payload, list):
        return [_rewrite_paths(item, src_root, dst_root) for item in payload]
    if isinstance(payload, str) and payload.startswith(src):
        return dst + payload[len(src) :]
    return payload


def command_plan(args: argparse.Namespace) -> None:
    pipeline = _load_or_default_config(args.config, args.settings)
    if args.dataset_root is not None:
        if pipeline.detection_dataset:
            pipeline.detection_dataset.root = resolve_dataset_root(args.dataset_root)
        if pipeline.classification_dataset:
            pipeline.classification_dataset.root = resolve_dataset_root(args.dataset_root)
    payload = pipeline.to_dict()
    print(json.dumps(payload, ensure_ascii=False, indent=2))


def command_run(args: argparse.Namespace) -> None:
    pipeline = _load_or_default_config(args.config, args.settings)
    task = TaskType(str(args.task))
    tier = ModelTier(str(args.tier))
    _filter_pipeline_candidates_by_task_tier(pipeline, task, tier)
    lane = lane_key(task, tier)

    logs_base = pipeline.logs_root if args.logs_root is None else Path(args.logs_root)
    pipeline.logs_root = logs_base / lane

    logger = RunLogger(logs_root=pipeline.logs_root)

    output_base = (
        pipeline.output_root if args.output_root is None else Path(args.output_root)
    )
    final_output_root = output_base / lane / logger.run_id
    staging_output_root = output_base / lane / f".tmp_{logger.run_id}"
    pipeline.output_root = staging_output_root
    if args.dataset_root is not None:
        if pipeline.detection_dataset:
            pipeline.detection_dataset.root = resolve_dataset_root(args.dataset_root)
        if pipeline.classification_dataset:
            pipeline.classification_dataset.root = resolve_dataset_root(args.dataset_root)

    dataset_adapter = build_dataset_adapter(args.dataset_adapter)

    try:
        result = run_experiment(pipeline=pipeline, dataset_adapter=dataset_adapter)
    except BaseException:
        shutil.rmtree(staging_output_root, ignore_errors=True)
        shutil.rmtree(logger.run_dir, ignore_errors=True)
        raise

    if staging_output_root.exists():
        shutil.move(str(staging_output_root), str(final_output_root))

    result = _rewrite_paths(result, staging_output_root, final_output_root)
    pipeline.output_root = final_output_root

    logger.save("pipeline.json", pipeline.to_dict())
    summary_path = logger.save("summary.json", result)

    comparison_path_csv = logger.run_dir / "comparison.csv"
    comparison_path_json = logger.run_dir / "comparison.json"
    save_comparison(
        comparison=result["comparison"],
        output_csv=comparison_path_csv,
        output_json=comparison_path_json,
    )

    previous_summary = logger.find_previous_summary()
    comparison_prev_csv: Path | None = None
    comparison_prev_json: Path | None = None
    if previous_summary is not None:
        comparison_prev = compare_summary_files([previous_summary, summary_path])
        comparison_prev_csv = logger.run_dir / "comparison_with_previous.csv"
        comparison_prev_json = logger.run_dir / "comparison_with_previous.json"
        save_comparison(
            comparison=comparison_prev,
            output_csv=comparison_prev_csv,
            output_json=comparison_prev_json,
        )

    timeline_entry = _build_compare_timeline_entry(
        task=task,
        tier=tier,
        run_id=logger.run_id,
        previous_summary_path=previous_summary,
        current_summary_path=summary_path,
        comparison_json_path=comparison_prev_json,
    )
    timeline_path = logger.append_timeline("summary_compare_timeline.jsonl", timeline_entry)

    output = {
        "lane": lane,
        "task": task.value,
        "tier": tier.value,
        "candidate_id": pipeline.candidates[0].candidate_id,
        "run_id": logger.run_id,
        "output_root": str(pipeline.output_root),
        "summary_path": str(summary_path),
        "comparison_csv": str(comparison_path_csv),
        "comparison_json": str(comparison_path_json),
        "comparison_with_previous_csv": (
            str(comparison_prev_csv) if comparison_prev_csv else None
        ),
        "comparison_with_previous_json": (
            str(comparison_prev_json) if comparison_prev_json else None
        ),
        "timeline_path": str(timeline_path),
        "winner": result["comparison"].get("overall_winner"),
    }
    print(json.dumps(output, ensure_ascii=False, indent=2))


def command_crop_dataset(args: argparse.Namespace) -> None:
    pipeline = _load_or_default_config(args.config, args.settings)
    crop_cfg = pipeline.crop_generation

    framework = (
        crop_cfg.framework
        if args.framework is None
        else FrameworkKind(str(args.framework))
    )
    detector_model_path = (
        crop_cfg.detector_model_path
        if args.detector_model is None
        else Path(args.detector_model)
    )
    source_root = crop_cfg.source_root if args.source_root is None else Path(args.source_root)
    output_root = crop_cfg.output_root if args.output_root is None else Path(args.output_root)
    score_threshold = (
        crop_cfg.score_threshold
        if args.score_threshold is None
        else float(args.score_threshold)
    )
    max_crops_per_image = (
        crop_cfg.max_crops_per_image
        if args.max_crops_per_image is None
        else int(args.max_crops_per_image)
    )

    backend = build_cropper_backend(framework)
    cropper = DatasetCropper(
        backend=backend,
        detector_model_path=detector_model_path,
        score_threshold=score_threshold,
        max_crops_per_image=max_crops_per_image,
    )
    summary = cropper.run(source_root=source_root, output_root=output_root)
    print(json.dumps(summary.__dict__, ensure_ascii=False, indent=2))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Bird monitoring model trainer with multi-framework orchestration"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    plan_parser = subparsers.add_parser("plan", help="show effective pipeline config")
    plan_parser.add_argument("--config", default=None, help="pipeline config json path")
    plan_parser.add_argument(
        "--settings", default="settings.toml", help="global settings toml path"
    )
    plan_parser.add_argument("--dataset-root", default=None)
    plan_parser.set_defaults(func=command_plan)

    run_parser = subparsers.add_parser("run", help="run candidate training pipeline")
    run_parser.add_argument("--config", default=None, help="pipeline config json path")
    run_parser.add_argument(
        "--settings", default="settings.toml", help="global settings toml path"
    )
    run_parser.add_argument("--dataset-root", default=None)
    run_parser.add_argument(
        "--task",
        required=True,
        choices=[TaskType.DETECTION.value, TaskType.CLASSIFICATION.value],
        help="required: choose task type for this run",
    )
    run_parser.add_argument(
        "--tier",
        required=True,
        choices=[ModelTier.LIGHTWEIGHT.value, ModelTier.STANDARD.value],
        help="required: choose model tier for this run",
    )
    run_parser.add_argument(
        "--dataset-adapter",
        default="auto",
        help="placeholder | unified-bird-detection | auto",
    )
    run_parser.add_argument("--output-root", default=None)
    run_parser.add_argument("--logs-root", default=None)
    run_parser.set_defaults(func=command_run)

    crop_parser = subparsers.add_parser(
        "crop-dataset",
        help="generate classification crops using detector model",
    )
    crop_parser.add_argument("--config", default=None, help="pipeline config json path")
    crop_parser.add_argument(
        "--settings", default="settings.toml", help="global settings toml path"
    )
    crop_parser.add_argument(
        "--framework",
        type=str,
        default=None,
        choices=["yolo", "pytorch"],
        help="override framework defined in crop_generation",
    )
    crop_parser.add_argument("--detector-model", default=None)
    crop_parser.add_argument("--source-root", default=None)
    crop_parser.add_argument("--output-root", default=None)
    crop_parser.add_argument("--score-threshold", type=float, default=None)
    crop_parser.add_argument("--max-crops-per-image", type=int, default=None)
    crop_parser.set_defaults(func=command_crop_dataset)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)
