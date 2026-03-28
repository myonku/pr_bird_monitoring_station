from collections import defaultdict
import json
from pathlib import Path
from typing import Any

import torch
from torch.utils.data import Dataset
from torchvision.transforms import functional as tvf
from PIL import Image

from src.config import DatasetContract, TaskType
from src.models.common import IMAGE_EXTENSIONS
from src.models.dataset_model import DatasetBundle


class UnifiedBirdDetectionDatasetAdapter:
    """适配 CUB 转换后的单类检测数据结构，用于统一鸟类检测任务。"""

    REQUIRED_RELATIVE_PATHS = (
        Path("images/train"),
        Path("images/val"),
        Path("labels/train"),
        Path("labels/val"),
        Path("annotations/instances_train.json"),
        Path("annotations/instances_val.json"),
        Path("yolo.yaml"),
    )

    def load(self, contract: DatasetContract) -> DatasetBundle:
        if contract.task != TaskType.DETECTION:
            raise ValueError(
                "UnifiedBirdDetectionDatasetAdapter only supports detection task"
            )

        root = contract.root.expanduser().resolve()
        self._validate_layout(root)

        train_items = self._count_images(root / "images" / "train")
        val_items = self._count_images(root / "images" / "val")
        test_items = self._count_images(root / "images" / "test")

        ann_train = self._read_coco_count(root / "annotations" / "instances_train.json")
        ann_val = self._read_coco_count(root / "annotations" / "instances_val.json")
        ann_test = self._read_coco_count(root / "annotations" / "instances_test.json")

        yolo_yaml = self._read_yolo_yaml(root / "yolo.yaml")
        dataset_meta = self._read_optional_json(root / "dataset_meta.json")

        metadata = {
            "status": "ready",
            "schema": "unified_bird_detection_v1",
            "root": str(root),
            "task": contract.task.value,
            "label_policy": contract.label_policy.value,
            "notes": contract.notes,
            "yolo_yaml": yolo_yaml,
            "dataset_meta": dataset_meta,
            "splits": {
                "train": {
                    "images": train_items,
                    "annotations": ann_train,
                },
                "val": {
                    "images": val_items,
                    "annotations": ann_val,
                },
                "test": {
                    "images": test_items,
                    "annotations": ann_test,
                },
            },
            "paths": {
                "yolo": {
                    "yaml": str(root / "yolo.yaml"),
                    "images_train": str(root / "images" / "train"),
                    "images_val": str(root / "images" / "val"),
                    "images_test": str(root / "images" / "test"),
                    "labels_train": str(root / "labels" / "train"),
                    "labels_val": str(root / "labels" / "val"),
                    "labels_test": str(root / "labels" / "test"),
                },
                "coco": {
                    "train": str(root / "annotations" / "instances_train.json"),
                    "val": str(root / "annotations" / "instances_val.json"),
                    "test": str(root / "annotations" / "instances_test.json"),
                },
            },
        }

        return DatasetBundle(
            dataset_id=contract.dataset_id,
            train_items=train_items,
            val_items=val_items,
            classes=["bird"],
            metadata=metadata,
        )

    def _validate_layout(self, root: Path) -> None:
        missing = [
            str(item)
            for item in self.REQUIRED_RELATIVE_PATHS
            if not (root / item).exists()
        ]
        if missing:
            joined = ", ".join(missing)
            raise FileNotFoundError(
                "unified detection dataset layout invalid, missing: " + joined
            )

    @staticmethod
    def _count_images(path: Path) -> int:
        if not path.exists():
            return 0
        return sum(
            1 for file in path.rglob("*") if file.suffix.lower() in IMAGE_EXTENSIONS
        )

    @staticmethod
    def _read_coco_count(path: Path) -> int:
        if not path.exists():
            return 0
        payload = json.loads(path.read_text(encoding="utf-8"))
        return len(payload.get("images", []))

    @staticmethod
    def _read_yolo_yaml(path: Path) -> dict[str, Any]:
        content = path.read_text(encoding="utf-8")
        result: dict[str, Any] = {}
        for raw_line in content.splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            if ":" not in line:
                continue
            key, value = line.split(":", 1)
            result[key.strip()] = value.strip()
        return result

    @staticmethod
    def _read_optional_json(path: Path) -> dict[str, Any] | None:
        if not path.exists():
            return None
        return json.loads(path.read_text(encoding="utf-8"))


class CocoDetectionDataset(Dataset):
    """基于 COCO 注释格式的检测数据集，适配 Faster R-CNN 训练输入。"""

    def __init__(self, annotation_path: Path, images_root: Path) -> None:
        payload = json.loads(annotation_path.read_text(encoding="utf-8"))
        self.images_root = images_root
        self.dataset_root = images_root.parents[1] if len(images_root.parents) >= 2 else images_root
        self.image_infos = payload.get("images", [])
        self.annotations_by_image: dict[int, list[dict[str, Any]]] = defaultdict(list)
        for ann in payload.get("annotations", []):
            self.annotations_by_image[int(ann.get("image_id", -1))].append(ann)

    def _resolve_image_path(self, file_name: str) -> Path:
        normalized = file_name.replace("\\", "/")
        file_path = Path(normalized)
        if file_path.is_absolute():
            return file_path

        parts = file_path.parts
        if len(parts) >= 3 and parts[0] == "images" and parts[1] in {"train", "val", "test"}:
            candidate = self.dataset_root / file_path
            if candidate.exists():
                return candidate

        if len(parts) >= 2 and parts[0] in {"train", "val", "test"}:
            candidate = self.images_root.parent / file_path
            if candidate.exists():
                return candidate

        return self.images_root / file_path

    def __len__(self) -> int:
        return len(self.image_infos)

    def __getitem__(self, index: int) -> tuple[torch.Tensor, dict[str, torch.Tensor]]:
        info = self.image_infos[index]
        image_id = int(info["id"])
        image_path = self._resolve_image_path(str(info["file_name"]))
        with Image.open(image_path) as image:
            image = image.convert("RGB")
            width, height = image.size
            image_tensor = tvf.pil_to_tensor(image).float() / 255.0

        boxes: list[list[float]] = []
        for ann in self.annotations_by_image.get(image_id, []):
            x, y, w, h = ann.get("bbox", [0.0, 0.0, 0.0, 0.0])
            if w <= 1.0 or h <= 1.0:
                continue
            x1 = max(0.0, min(float(width - 1), float(x)))
            y1 = max(0.0, min(float(height - 1), float(y)))
            x2 = max(x1 + 1.0, min(float(width), float(x + w)))
            y2 = max(y1 + 1.0, min(float(height), float(y + h)))
            boxes.append([x1, y1, x2, y2])

        if boxes:
            boxes_tensor = torch.tensor(boxes, dtype=torch.float32)
            labels = torch.ones((len(boxes),), dtype=torch.int64)
            areas = (boxes_tensor[:, 2] - boxes_tensor[:, 0]) * (
                boxes_tensor[:, 3] - boxes_tensor[:, 1]
            )
            iscrowd = torch.zeros((len(boxes),), dtype=torch.int64)
        else:
            boxes_tensor = torch.zeros((0, 4), dtype=torch.float32)
            labels = torch.zeros((0,), dtype=torch.int64)
            areas = torch.zeros((0,), dtype=torch.float32)
            iscrowd = torch.zeros((0,), dtype=torch.int64)

        target = {
            "boxes": boxes_tensor,
            "labels": labels,
            "image_id": torch.tensor([image_id], dtype=torch.int64),
            "area": areas,
            "iscrowd": iscrowd,
        }
        return image_tensor, target
