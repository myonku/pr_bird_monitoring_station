from src.models.dataset_model import DatasetBundle
from src.config import DatasetContract


class PlaceholderDatasetAdapter:
    """占位数据集适配器：在数据集规范未定前，返回空数据描述。"""

    def load(self, contract: DatasetContract) -> DatasetBundle:
        metadata = {
            "root": str(contract.root),
            "task": contract.task.value,
            "label_policy": contract.label_policy.value,
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
