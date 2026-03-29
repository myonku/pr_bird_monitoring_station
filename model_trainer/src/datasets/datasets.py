from pathlib import Path
from typing import Literal

from src.datasets.detection_dataset import UnifiedBirdDetectionDatasetAdapter
from src.datasets.classification_dataset import (
    BirdClassificationDatasetAdapter,
)
from src.config import DatasetContract, PipelineConfig, TaskType

from src.models.dataset_model import DatasetBundle


AdapterMode = Literal[
    "unified-bird-detection",
    "bird-classification",
    "auto",
]


class DatasetService:
    """训练侧数据集加载入口，按模式做最小路由。"""

    def __init__(self, mode: AdapterMode) -> None:
        self.mode = mode
        self._detection = UnifiedBirdDetectionDatasetAdapter()
        self._classification = BirdClassificationDatasetAdapter()

    def load(self, contract: DatasetContract) -> DatasetBundle:
        if contract.task == TaskType.DETECTION:
            return self._detection.load(contract)

        if self.mode in {"unified-bird-detection", "bird-classification", "auto"}:
            return self._classification.load(contract)

        raise ValueError(f"unsupported dataset adapter mode: {self.mode}")


def build_dataset_adapter(name: str) -> DatasetService:
    adapter_key = name.strip().lower()
    if adapter_key in {"default", "none"}:
        return DatasetService("auto")
    if adapter_key in {"unified-bird-detection", "cub-bird-detection", "det-bird"}:
        return DatasetService("unified-bird-detection")
    if adapter_key in {"bird-classification", "cls-bird", "classification"}:
        return DatasetService("bird-classification")
    if adapter_key in {"auto", "smart"}:
        return DatasetService("auto")
    raise ValueError(
        f"Unsupported dataset adapter: {name}. "
        "Current available adapters: unified-bird-detection, "
        "bird-classification, auto"
    )


def resolve_dataset_root(dataset_root: str | Path) -> Path:
    return Path(dataset_root).expanduser().resolve()


def resolve_contract_for_task(
    pipeline: PipelineConfig,
    task: TaskType,
) -> DatasetContract:
    """按任务路由数据集契约；兼容旧版单 dataset 配置。"""
    if task == TaskType.DETECTION and pipeline.detection_dataset is not None:
        return pipeline.detection_dataset
    if task == TaskType.CLASSIFICATION and pipeline.classification_dataset is not None:
        return pipeline.classification_dataset
    raise ValueError(f"dataset contract not configured for task={task.value}")
