from __future__ import annotations

import argparse
import json
from pathlib import Path

from src.config import (
    PipelineConfig,
    build_default_pipeline_config,
    load_pipeline_from_settings_toml,
    load_pipeline_config,
)
from src.core.comparator import compare_summary_files, save_comparison
from src.core.datasets import build_dataset_adapter, resolve_dataset_root
from src.core.engine import run_experiment
from src.logger import RunLogger


def _load_or_default_config(path: str | None, settings_path: str) -> PipelineConfig:
    if path:
        return load_pipeline_config(Path(path))

    settings_file = Path(settings_path)
    if settings_file.exists() and settings_file.stat().st_size > 0:
        return load_pipeline_from_settings_toml(settings_file)

    return build_default_pipeline_config()


def command_plan(args: argparse.Namespace) -> None:
    pipeline = _load_or_default_config(args.config, args.settings)
    if pipeline.dataset:
        pipeline.dataset.root = resolve_dataset_root(args.dataset_root)
    payload = pipeline.to_dict()
    print(json.dumps(payload, ensure_ascii=False, indent=2))


def command_run(args: argparse.Namespace) -> None:
    pipeline = _load_or_default_config(args.config, args.settings)
    pipeline.output_root = Path(args.output_root)
    pipeline.logs_root = Path(args.logs_root)
    if pipeline.dataset:
        pipeline.dataset.root = resolve_dataset_root(args.dataset_root)

    dataset_adapter = build_dataset_adapter(args.dataset_adapter)
    logger = RunLogger(logs_root=pipeline.logs_root, experiment_name=pipeline.experiment_name)

    logger.save("pipeline.json", pipeline.to_dict())
    result = run_experiment(pipeline=pipeline, dataset_adapter=dataset_adapter)
    summary_path = logger.save("summary.json", result)

    comparison_path_csv = logger.run_dir / "comparison.csv"
    comparison_path_json = logger.run_dir / "comparison.json"
    save_comparison(
        comparison=result["comparison"],
        output_csv=comparison_path_csv,
        output_json=comparison_path_json,
    )

    output = {
        "run_id": logger.run_id,
        "summary_path": str(summary_path),
        "comparison_csv": str(comparison_path_csv),
        "comparison_json": str(comparison_path_json),
        "winner": result["comparison"].get("overall_winner"),
    }
    print(json.dumps(output, ensure_ascii=False, indent=2))


def command_compare(args: argparse.Namespace) -> None:
    summary_paths = [Path(item) for item in args.summaries]
    comparison = compare_summary_files(summary_paths)
    output_csv = Path(args.output_csv)
    output_json = Path(args.output_json)
    save_comparison(comparison=comparison, output_csv=output_csv, output_json=output_json)
    print(json.dumps(comparison, ensure_ascii=False, indent=2))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Bird monitoring model trainer with multi-framework orchestration"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    plan_parser = subparsers.add_parser("plan", help="show effective pipeline config")
    plan_parser.add_argument("--config", default=None, help="pipeline config json path")
    plan_parser.add_argument("--settings", default="settings.toml", help="global settings toml path")
    plan_parser.add_argument("--dataset-root", default="dataset")
    plan_parser.set_defaults(func=command_plan)

    run_parser = subparsers.add_parser("run", help="run candidate training pipeline")
    run_parser.add_argument("--config", default=None, help="pipeline config json path")
    run_parser.add_argument("--settings", default="settings.toml", help="global settings toml path")
    run_parser.add_argument("--dataset-root", default="dataset")
    run_parser.add_argument("--dataset-adapter", default="placeholder")
    run_parser.add_argument("--output-root", default="output_models")
    run_parser.add_argument("--logs-root", default="logs")
    run_parser.set_defaults(func=command_run)

    compare_parser = subparsers.add_parser("compare", help="compare summary files")
    compare_parser.add_argument("--summaries", nargs="+", required=True)
    compare_parser.add_argument("--output-csv", default="logs/model_comparison.csv")
    compare_parser.add_argument("--output-json", default="logs/model_comparison.json")
    compare_parser.set_defaults(func=command_compare)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)

