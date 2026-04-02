from pathlib import Path
from typing import Any

from src.config import PipelineConfig
from src.datasets.datasets import DatasetService, resolve_contract_for_task
from src.evaluator.comparator import compare_records
from src.factory.model_factory import build_backend_registry


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


def run_experiment(
    pipeline: PipelineConfig,
    dataset_adapter: DatasetService,
    backend_registry: dict | None = None,
) -> dict[str, Any]:
    if not pipeline.candidates:
        raise ValueError("pipeline.candidates is empty")

    registry: dict = backend_registry or build_backend_registry()
    task_dataset_cache: dict[str, Any] = {}
    for candidate in pipeline.candidates:
        task_key = candidate.task.value
        if task_key in task_dataset_cache:
            continue
        contract = resolve_contract_for_task(pipeline=pipeline, task=candidate.task)
        task_dataset_cache[task_key] = dataset_adapter.load(contract)

    run_root = Path(pipeline.output_root)
    run_root.mkdir(parents=True, exist_ok=True)

    results: list[dict[str, Any]] = []
    for candidate in pipeline.candidates:
        backend = registry.get(candidate.framework)
        if backend is None:
            raise ValueError(
                f"No backend registered for framework={candidate.framework}"
            )

        dataset_bundle = task_dataset_cache[candidate.task.value]
        candidate_dir = run_root
        output = backend.train(
            candidate=candidate,
            dataset=dataset_bundle,
            output_dir=candidate_dir,
        )
        results.append(_record_from_output(output))

    comparison = compare_records(results)
    current = results[0]
    return {
        "task": current["task"],
        "tier": current["tier"],
        "candidate_id": current["candidate_id"],
        "datasets": {
            key: bundle.metadata for key, bundle in task_dataset_cache.items()
        },
        "results": results,
        "comparison": comparison,
    }
