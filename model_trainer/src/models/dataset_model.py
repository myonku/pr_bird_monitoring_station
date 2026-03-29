from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from src.models.common import LabelPolicy, TaskType


@dataclass(slots=True)
class DatasetBundle:
    """标准化后的数据集包，供训练后端读取。"""

    dataset_id: str
    train_items: int = 0
    val_items: int = 0
    classes: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class DatasetContract:
    """数据集契约：仅定义统一元信息，不绑定具体目录结构。"""

    dataset_id: str
    root: Path
    task: TaskType
    label_policy: LabelPolicy = LabelPolicy.AS_IS
    label_file_name: str = "class.txt"
    metadata_path: Path | None = None
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["root"] = str(self.root)
        payload["task"] = self.task.value
        payload["label_policy"] = self.label_policy.value
        if self.metadata_path is not None:
            payload["metadata_path"] = str(self.metadata_path)
        return payload


@dataclass(slots=True)
class ClassificationImageItem:
    """分类数据集中的单张图片项，包含所属类别和路径信息。"""

    class_id: str
    class_name: str
    image_path: Path
    relative_path: Path


@dataclass(slots=True)
class ClassificationLayout:
    """描述分类数据集的目录结构和文件分布情况。"""

    root: Path
    class_file: Path
    classes: dict[str, str]
    images: list[ClassificationImageItem]
    class_image_counts: dict[str, int]
    extra_top_level_dirs: list[str]
