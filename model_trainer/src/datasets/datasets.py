from pathlib import Path
from typing import Literal

from src.datasets.detection_dataset import UnifiedBirdDetectionDatasetAdapter
from src.datasets.classification_dataset import PlaceholderDatasetAdapter
from src.config import DatasetContract, PipelineConfig, TaskType

from src.models.dataset_model import DatasetBundle


AdapterMode = Literal["placeholder", "unified-bird-detection", "auto"]


class DatasetService:
    """训练侧数据集加载入口，按模式做最小路由。"""

    def __init__(self, mode: AdapterMode) -> None:
        self.mode = mode
        self._detection = UnifiedBirdDetectionDatasetAdapter()
        self._placeholder = PlaceholderDatasetAdapter()

    def load(self, contract: DatasetContract) -> DatasetBundle:
        if contract.task == TaskType.DETECTION:
            if self.mode == "placeholder":
                raise ValueError(
                    "Detection task does not support placeholder dataset adapter. "
                    "Use unified-bird-detection or auto."
                )
            return self._detection.load(contract)

        if self.mode == "placeholder":
            return self._placeholder.load(contract)

        if self.mode in {"unified-bird-detection", "auto"}:
            return self._placeholder.load(contract)

        return self._placeholder.load(contract)


def build_dataset_adapter(name: str) -> DatasetService:
    adapter_key = name.strip().lower()
    if adapter_key in {"placeholder", "default", "none"}:
        return DatasetService("placeholder")
    if adapter_key in {"unified-bird-detection", "cub-bird-detection", "det-bird"}:
        return DatasetService("unified-bird-detection")
    if adapter_key in {"auto", "smart"}:
        return DatasetService("auto")
    raise ValueError(
        f"Unsupported dataset adapter: {name}. "
        "Current available adapters: placeholder, unified-bird-detection, auto"
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
