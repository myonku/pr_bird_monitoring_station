from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from src.config import DatasetContract


@dataclass(slots=True)
class DatasetBundle:
    """标准化后的数据集包，供训练后端读取。"""

    dataset_id: str
    train_items: int = 0
    val_items: int = 0
    classes: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


class DatasetAdapter(Protocol):
    def load(self, contract: DatasetContract) -> DatasetBundle:
        """根据契约读取数据集并返回统一的数据集描述。"""
        ...


class PlaceholderDatasetAdapter:
    """占位数据集适配器：在数据集规范未定前，返回空数据描述。"""

    def load(self, contract: DatasetContract) -> DatasetBundle:
        metadata = {
            "root": str(contract.root),
            "task": contract.task.value,
            "metadata_path": (
                str(contract.metadata_path) if contract.metadata_path else None
            ),
            "notes": contract.notes,
            "status": "placeholder",
        }
        return DatasetBundle(
            dataset_id=contract.dataset_id,
            train_items=0,
            val_items=0,
            classes=[],
            metadata=metadata,
        )


def build_dataset_adapter(name: str) -> DatasetAdapter:
    adapter_key = name.strip().lower()
    if adapter_key in {"placeholder", "default", "none"}:
        return PlaceholderDatasetAdapter()
    raise ValueError(
        f"Unsupported dataset adapter: {name}. "
        "Current available adapters: placeholder"
    )


def resolve_dataset_root(dataset_root: str | Path) -> Path:
    return Path(dataset_root).expanduser().resolve()
