import argparse
from dataclasses import asdict
import json
import shutil
from pathlib import Path

from src.config import (
    ModelTier,
    TaskType,
)
from src.cli_tools.model_selector import (
    select_detection_model_for_tier,
    select_model_for_task_tier,
)
from src.cli_tools.pipeline import (
    filter_pipeline_candidates_by_task_tier,
    load_or_default_config,
    rewrite_paths,
)
from src.cli_tools.timeline import build_compare_timeline_entry
from src.cropper.dataset_cropper import DatasetCropper, build_cropper_backend
from src.datasets.datasets import build_dataset_adapter, resolve_dataset_root
from src.evaluator.comparator import compare_summary_files, save_comparison
from src.engine import run_experiment
from src.models.common import lane_key
from src.logger import RunLogger


def command_plan(args: argparse.Namespace) -> None:
    pipeline = load_or_default_config(args.config, args.settings)
    if args.dataset_root is not None:
        if pipeline.detection_dataset:
            pipeline.detection_dataset.root = resolve_dataset_root(args.dataset_root)
        if pipeline.classification_dataset:
            pipeline.classification_dataset.root = resolve_dataset_root(
                args.dataset_root
            )
    payload = pipeline.to_dict()
    print(json.dumps(payload, ensure_ascii=False, indent=2))


def command_run(args: argparse.Namespace) -> None:
    pipeline = load_or_default_config(args.config, args.settings)
    task = TaskType(str(args.task))
    tier = ModelTier(str(args.tier))
    filter_pipeline_candidates_by_task_tier(pipeline, task, tier)
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
            pipeline.classification_dataset.root = resolve_dataset_root(
                args.dataset_root
            )

    dataset_adapter = build_dataset_adapter(args.dataset_adapter)

    try:
        result = run_experiment(pipeline=pipeline, dataset_adapter=dataset_adapter)
    except BaseException:
        shutil.rmtree(staging_output_root, ignore_errors=True)
        shutil.rmtree(logger.run_dir, ignore_errors=True)
        raise

    if staging_output_root.exists():
        shutil.move(str(staging_output_root), str(final_output_root))

    result = rewrite_paths(result, staging_output_root, final_output_root)
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

    timeline_entry = build_compare_timeline_entry(
        task=task,
        tier=tier,
        run_id=logger.run_id,
        previous_summary_path=previous_summary,
        current_summary_path=summary_path,
        comparison_json_path=comparison_prev_json,
    )
    timeline_path = logger.append_timeline(
        "summary_compare_timeline.jsonl", timeline_entry
    )

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
    pipeline = load_or_default_config(args.config, args.settings)
    crop_cfg = pipeline.crop_generation
    tier = ModelTier(str(args.tier))
    lane = lane_key(TaskType.DETECTION, tier)

    logs_base = pipeline.logs_root if args.logs_root is None else Path(args.logs_root)
    logs_lane_root = logs_base / lane
    selected_model_payload: dict[str, object]
    try:
        selected = select_detection_model_for_tier(
            logs_lane_root=logs_lane_root,
            tier=tier,
            selection_limit=crop_cfg.max_selection_candidates,
        )
        framework = selected.framework
        detector_model_path = selected.model_path
        selected_model_payload = {
            "source": "logs_topk",
            "candidate_id": selected.candidate_id,
            "model_name": selected.model_name,
            "framework": selected.framework.value,
            "score": selected.score,
            "model_path": str(selected.model_path),
            "run_id": selected.run_id,
            "summary_path": str(selected.summary_path),
        }
    except FileNotFoundError as exc:
        fallback_path = crop_cfg.detector_model_path.expanduser().resolve()
        if not (fallback_path.exists() and fallback_path.is_file()):
            raise SystemExit(
                "auto model selection failed and fallback model path is invalid. "
                f"selection_error={exc}; fallback_path={fallback_path}"
            ) from exc

        framework = crop_cfg.framework
        detector_model_path = fallback_path
        selected_model_payload = {
            "source": "crop_generation_fallback",
            "candidate_id": None,
            "model_name": None,
            "framework": framework.value,
            "score": None,
            "model_path": str(fallback_path),
            "run_id": None,
            "summary_path": None,
        }
    source_root = (
        crop_cfg.source_root if args.source_root is None else Path(args.source_root)
    )
    output_root = (
        crop_cfg.output_root if args.output_root is None else Path(args.output_root)
    )
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
        label_file_name=crop_cfg.label_file_name,
        min_box_area_ratio=crop_cfg.min_box_area_ratio,
        max_box_area_ratio=crop_cfg.max_box_area_ratio,
        min_box_edge_margin_ratio=crop_cfg.min_box_edge_margin_ratio,
        max_images_per_class=crop_cfg.max_images_per_class,
        padding_ratio=crop_cfg.padding_ratio,
        show_progress=crop_cfg.show_progress,
        progress_interval=crop_cfg.progress_interval,
    )
    summary = cropper.run(source_root=source_root, output_root=output_root)
    payload = asdict(summary)
    payload.update(
        {
            "task": TaskType.DETECTION.value,
            "tier": tier.value,
            "lane": lane,
            "selection_limit": crop_cfg.max_selection_candidates,
            "selected_model": selected_model_payload,
        }
    )
    print(json.dumps(payload, ensure_ascii=False, indent=2))


def command_export_model(args: argparse.Namespace) -> None:
    pipeline = load_or_default_config(args.config, args.settings)
    task = TaskType(str(args.task))
    tier = ModelTier(str(args.tier))
    selection_limit = int(args.max_selection_candidates)
    if selection_limit < 1:
        raise SystemExit("max_selection_candidates must be >= 1")

    lane = lane_key(task, tier)
    logs_base = pipeline.logs_root if args.logs_root is None else Path(args.logs_root)
    logs_lane_root = logs_base / lane

    selected = select_model_for_task_tier(
        logs_lane_root=logs_lane_root,
        task=task,
        tier=tier,
        selection_limit=selection_limit,
    )

    output_dir = Path(str(args.output)).expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    target_path = output_dir / selected.model_path.name
    shutil.copy2(selected.model_path, target_path)

    payload = {
        "task": task.value,
        "tier": tier.value,
        "lane": lane,
        "selection_limit": selection_limit,
        "source": "logs_topk",
        "output": str(output_dir),
        "exported_model_path": str(target_path),
        "selected_model": {
            "candidate_id": selected.candidate_id,
            "model_name": selected.model_name,
            "framework": selected.framework.value,
            "score": selected.score,
            "model_path": str(selected.model_path),
            "run_id": selected.run_id,
            "summary_path": str(selected.summary_path),
        },
    }
    print(json.dumps(payload, ensure_ascii=False, indent=2))


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
        help="unified-bird-detection | bird-classification | auto",
    )
    run_parser.add_argument("--output-root", default=None)
    run_parser.add_argument("--logs-root", default=None)
    run_parser.set_defaults(func=command_run)

    crop_parser = subparsers.add_parser(
        "crop-dataset",
        help="generate classification crops using detector model (logs auto-select with config fallback)",
    )
    crop_parser.add_argument("--config", default=None, help="pipeline config json path")
    crop_parser.add_argument(
        "--settings", default="settings.toml", help="global settings toml path"
    )
    crop_parser.add_argument(
        "--tier",
        required=True,
        choices=[ModelTier.LIGHTWEIGHT.value, ModelTier.STANDARD.value],
        help="required: choose detection tier to auto-select best detector from logs",
    )
    crop_parser.add_argument(
        "--logs-root",
        default=None,
        help=(
            "override logs root for model selection; lane subdir is resolved automatically; "
            "if selection fails, crop_generation detector_model_path is used as fallback"
        ),
    )
    crop_parser.add_argument("--source-root", default=None)
    crop_parser.add_argument("--output-root", default=None)
    crop_parser.add_argument("--score-threshold", type=float, default=None)
    crop_parser.add_argument("--max-crops-per-image", type=int, default=None)
    crop_parser.set_defaults(func=command_crop_dataset)

    export_parser = subparsers.add_parser(
        "export-model",
        help="export selected model artifact by task+tier from top-k logs",
    )
    export_parser.add_argument(
        "--config",
        default=None,
        help="pipeline config json path",
    )
    export_parser.add_argument(
        "--settings",
        default="settings.toml",
        help="global settings toml path",
    )
    export_parser.add_argument(
        "--task",
        required=True,
        choices=[TaskType.DETECTION.value, TaskType.CLASSIFICATION.value],
        help="required: choose task type for model export",
    )
    export_parser.add_argument(
        "--tier",
        required=True,
        choices=[ModelTier.LIGHTWEIGHT.value, ModelTier.STANDARD.value],
        help="required: choose model tier for model export",
    )
    export_parser.add_argument(
        "--max-selection-candidates",
        "--max_selection_candidates",
        dest="max_selection_candidates",
        required=True,
        type=int,
        help="required: only search top-N ranked candidates in logs",
    )
    export_parser.add_argument(
        "--output",
        required=True,
        help="required: target directory to export selected model artifact",
    )
    export_parser.add_argument(
        "--logs-root",
        default=None,
        help="override logs root for model selection; lane subdir is resolved automatically",
    )
    export_parser.set_defaults(func=command_export_model)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)
