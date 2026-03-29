from src.config import DatasetContract
from src.datasets.classification_layout import discover_classification_layout
from src.models.dataset_model import DatasetBundle


class BirdClassificationDatasetAdapter:
    """分类数据集适配器：解析分类数据集目录结构。"""

    def load(self, contract: DatasetContract) -> DatasetBundle:
        layout = discover_classification_layout(
            contract.root,
            label_file_name=contract.label_file_name,
        )
        class_ids = list(layout.classes.keys())
        class_names = [layout.classes[class_id] for class_id in class_ids]
        class_dirs = {class_id: str(layout.root / class_id) for class_id in class_ids}
        classes_meta = [
            {
                "class_id": class_id,
                "class_name": layout.classes[class_id],
                "images": layout.class_image_counts.get(class_id, 0),
            }
            for class_id in class_ids
        ]

        metadata = {
            "status": "ready",
            "schema": "bird_classification_v1",
            "root": str(layout.root),
            "task": contract.task.value,
            "label_policy": contract.label_policy.value,
            "label_file_name": contract.label_file_name,
            "metadata_path": (
                str(contract.metadata_path) if contract.metadata_path else None
            ),
            "notes": contract.notes,
            "class_count": len(class_ids),
            "total_images": len(layout.images),
            "classes": classes_meta,
            "extra_top_level_dirs": layout.extra_top_level_dirs,
            "paths": {
                "label_file": str(layout.class_file),
                "class_dirs": class_dirs,
            },
        }

        return DatasetBundle(
            dataset_id=contract.dataset_id,
            train_items=len(layout.images),
            val_items=0,
            classes=class_names,
            metadata=metadata,
        )
