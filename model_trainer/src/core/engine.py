from __future__ import annotations

from pathlib import Path
from typing import Any

from src.config import PipelineConfig
from src.core.comparator import compare_records
from src.core.contracts import EvaluationResult, Evaluator
from src.core.datasets import DatasetAdapter
from src.core.model_factory import TrainerBackend, build_backend_registry


def _best_model_path(
    records: list[dict[str, Any]],
    tier: str,
    task: str,
) -> str | None:
    matched = [
        item
        for item in records
        if item.get("tier") == tier and item.get("task") == task
    ]
    if not matched:
        return None

    if task == "detection":
        ranked = sorted(
            matched,
            key=lambda item: float(item.get("map50_95", 0.0) or 0.0),
            reverse=True,
        )
    else:
        ranked = sorted(
            matched, key=lambda item: float(item.get("top1", 0.0) or 0.0), reverse=True
        )

    winner = ranked[0]
    exported = winner.get("exported_paths", [])
    if exported:
        return str(exported[0])
    return str(winner.get("checkpoint_path")) if winner.get("checkpoint_path") else None


def _build_deployment_paths(
    pipeline: PipelineConfig, records: list[dict[str, Any]]
) -> dict[str, str | None]:
    auto_paths = {
        "edge_detection_model_path": _best_model_path(
            records, tier="lightweight", task="detection"
        ),
        "edge_classification_model_path": _best_model_path(
            records, tier="lightweight", task="classification"
        ),
        "server_detection_model_path": _best_model_path(
            records, tier="standard", task="detection"
        ),
        "server_classification_model_path": _best_model_path(
            records, tier="standard", task="classification"
        ),
    }

    manual = pipeline.deployment.to_dict()
    return {
        "edge_detection_model_path": manual["edge_detection_model_path"]
        or auto_paths["edge_detection_model_path"],
        "edge_classification_model_path": manual["edge_classification_model_path"]
        or auto_paths["edge_classification_model_path"],
        "server_detection_model_path": manual["server_detection_model_path"]
        or auto_paths["server_detection_model_path"],
        "server_classification_model_path": manual["server_classification_model_path"]
        or auto_paths["server_classification_model_path"],
    }


def _record_from_output(output: Any) -> dict[str, Any]:
    return {
        "candidate_id": output.candidate_id,
        "framework": output.framework,
        "model_name": output.model_name,
        "tier": output.tier,
        "task": output.task,
        "map50": output.map50,
        "map50_95": output.map50_95,
        "top1": output.top1,
        "latency_ms": output.latency_ms,
        "size_mb": output.size_mb,
        "checkpoint_path": output.checkpoint_path,
        "exported_paths": output.exported_paths,
    }


class DefaultEvaluator:
    def evaluate(self, records: list[dict[str, Any]]) -> EvaluationResult:
        compared = compare_records(records)
        return EvaluationResult(
            leaderboard=compared["leaderboard"],
            best_lightweight=compared["best_lightweight"],
            best_standard=compared["best_standard"],
            overall_winner=compared["overall_winner"],
        )


def run_experiment(
    pipeline: PipelineConfig,
    dataset_adapter: DatasetAdapter,
    backend_registry: dict | None = None,
    evaluator: Evaluator | None = None,
) -> dict[str, Any]:
    if not pipeline.dataset:
        raise ValueError("pipeline.dataset is required")

    registry: dict = backend_registry or build_backend_registry()
    dataset_bundle = dataset_adapter.load(pipeline.dataset)

    run_root = Path(pipeline.output_root) / pipeline.experiment_name
    run_root.mkdir(parents=True, exist_ok=True)

    results: list[dict[str, Any]] = []
    for candidate in pipeline.candidates:
        backend: TrainerBackend | None = registry.get(candidate.framework)
        if backend is None:
            raise ValueError(
                f"No backend registered for framework={candidate.framework}"
            )

        candidate_dir = run_root / candidate.candidate_id
        output = backend.train(
            candidate=candidate,
            dataset=dataset_bundle,
            output_dir=candidate_dir,
        )
        results.append(_record_from_output(output))

    active_evaluator = evaluator or DefaultEvaluator()
    comparison = active_evaluator.evaluate(results)
    deployment_paths = _build_deployment_paths(pipeline=pipeline, records=results)
    return {
        "project": pipeline.project_name,
        "experiment": pipeline.experiment_name,
        "dataset": dataset_bundle.metadata,
        "results": results,
        "deployment_paths": deployment_paths,
        "comparison": {
            "leaderboard": comparison.leaderboard,
            "best_lightweight": comparison.best_lightweight,
            "best_standard": comparison.best_standard,
            "overall_winner": comparison.overall_winner,
        },
    }
