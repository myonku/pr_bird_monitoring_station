from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from src.config import FrameworkKind, ModelCandidate
from src.core.datasets import DatasetBundle


@dataclass(slots=True)
class TrainingOutput:
    candidate_id: str
    framework: str
    model_name: str
    tier: str
    task: str
    map50: float
    map50_95: float
    top1: float
    latency_ms: float
    size_mb: float
    checkpoint_path: str
    exported_paths: list[str]


class TrainerBackend(Protocol):
    framework: FrameworkKind

    def train(
        self,
        candidate: ModelCandidate,
        dataset: DatasetBundle,
        output_dir: Path,
    ) -> TrainingOutput:
        """执行训练并返回标准化结果。"""
        ...


def _deterministic_score(seed_text: str, low: float, high: float) -> float:
    digest = hashlib.sha256(seed_text.encode("utf-8")).hexdigest()
    value = int(digest[:8], 16) / 0xFFFFFFFF
    return round(low + (high - low) * value, 4)


def _make_export_artifacts(
    output_dir: Path,
    candidate: ModelCandidate,
    formats: list[str],
) -> list[str]:
    export_dir = output_dir / "exports"
    export_dir.mkdir(parents=True, exist_ok=True)
    paths = []
    for item in formats:
        target = export_dir / f"{candidate.candidate_id}.{item}"
        target.write_text(
            (
                "placeholder artifact\n"
                f"framework={candidate.framework.value}\n"
                f"model={candidate.model_name}\n"
                f"tier={candidate.tier.value}\n"
            ),
            encoding="utf-8",
        )
        paths.append(str(target))
    return paths


class YoloBackend:
    framework = FrameworkKind.YOLO

    def train(
        self,
        candidate: ModelCandidate,
        dataset: DatasetBundle,
        output_dir: Path,
    ) -> TrainingOutput:
        output_dir.mkdir(parents=True, exist_ok=True)
        checkpoint = output_dir / f"{candidate.candidate_id}.pt"
        checkpoint.write_text(
            "placeholder yolo checkpoint\n"
            f"dataset={dataset.dataset_id}\n"
            f"model={candidate.model_name}\n",
            encoding="utf-8",
        )

        base = f"{candidate.candidate_id}:{candidate.model_name}:{dataset.dataset_id}"
        exported = _make_export_artifacts(
            output_dir, candidate, candidate.export_formats
        )
        return TrainingOutput(
            candidate_id=candidate.candidate_id,
            framework=candidate.framework.value,
            model_name=candidate.model_name,
            tier=candidate.tier.value,
            task=candidate.task.value,
            map50=_deterministic_score(base + ":map50", 0.45, 0.86),
            map50_95=_deterministic_score(base + ":map50_95", 0.25, 0.67),
            top1=0.0,
            latency_ms=_deterministic_score(base + ":latency", 8.0, 70.0),
            size_mb=_deterministic_score(base + ":size", 5.0, 120.0),
            checkpoint_path=str(checkpoint),
            exported_paths=exported,
        )


class PytorchBackend:
    framework = FrameworkKind.PYTORCH

    def train(
        self,
        candidate: ModelCandidate,
        dataset: DatasetBundle,
        output_dir: Path,
    ) -> TrainingOutput:
        output_dir.mkdir(parents=True, exist_ok=True)
        checkpoint = output_dir / f"{candidate.candidate_id}.ckpt"
        checkpoint.write_text(
            "placeholder pytorch checkpoint\n"
            f"dataset={dataset.dataset_id}\n"
            f"model={candidate.model_name}\n",
            encoding="utf-8",
        )

        base = f"{candidate.candidate_id}:{candidate.model_name}:{dataset.dataset_id}"
        exported = _make_export_artifacts(
            output_dir, candidate, candidate.export_formats
        )
        return TrainingOutput(
            candidate_id=candidate.candidate_id,
            framework=candidate.framework.value,
            model_name=candidate.model_name,
            tier=candidate.tier.value,
            task=candidate.task.value,
            map50=0.0,
            map50_95=0.0,
            top1=_deterministic_score(base + ":top1", 0.55, 0.92),
            latency_ms=_deterministic_score(base + ":latency", 6.0, 65.0),
            size_mb=_deterministic_score(base + ":size", 4.0, 180.0),
            checkpoint_path=str(checkpoint),
            exported_paths=exported,
        )


def build_backend_registry() -> dict[FrameworkKind, TrainerBackend]:
    return {
        FrameworkKind.YOLO: YoloBackend(),
        FrameworkKind.PYTORCH: PytorchBackend(),
    }
