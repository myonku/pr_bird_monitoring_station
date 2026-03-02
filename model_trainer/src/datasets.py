from __future__ import annotations

from pathlib import Path

from PIL import Image
from torch.utils.data import DataLoader, Dataset
from torchvision import transforms

IMAGE_EXTENSIONS = {".jpg", ".jpeg", ".png", ".bmp", ".webp"}


class CUB200Dataset(Dataset):
    """针对 CUB-200-2011 数据集的自定义 Dataset 实现。"""
    def __init__(
        self,
        root: Path,
        split: str,
        transform=None,
        class_to_idx: dict[str, int] | None = None,
    ) -> None:
        self.root = Path(root)
        self.split = split
        self.transform = transform
        split_dir = self.root / split
        if not split_dir.exists():
            raise FileNotFoundError(f"split directory not found: {split_dir}")

        class_dirs = sorted([path for path in split_dir.iterdir() if path.is_dir()])
        if class_to_idx is None:
            self.class_to_idx = {path.name: idx for idx, path in enumerate(class_dirs)}
        else:
            self.class_to_idx = class_to_idx

        self.samples: list[tuple[Path, int]] = []
        for class_dir in class_dirs:
            if class_dir.name not in self.class_to_idx:
                continue
            class_index = self.class_to_idx[class_dir.name]
            for image_path in sorted(class_dir.rglob("*")):
                if image_path.suffix.lower() in IMAGE_EXTENSIONS:
                    self.samples.append((image_path, class_index))

        if not self.samples:
            raise RuntimeError(f"no images found in {split_dir}")

        self.idx_to_class = {idx: name for name, idx in self.class_to_idx.items()}

    def __len__(self) -> int:
        return len(self.samples)

    def __getitem__(self, index: int):
        image_path, label = self.samples[index]
        with Image.open(image_path) as image:
            image = image.convert("RGB")
        if self.transform is not None:
            image = self.transform(image)
        return image, label


def _build_train_transform(image_size: int):
    return transforms.Compose(
        [
            transforms.Resize((image_size + 32, image_size + 32)),
            transforms.RandomResizedCrop(image_size, scale=(0.7, 1.0)),
            transforms.RandomHorizontalFlip(),
            transforms.ColorJitter(brightness=0.2, contrast=0.2, saturation=0.2),
            transforms.ToTensor(),
            transforms.Normalize(mean=[0.485, 0.456, 0.406], std=[0.229, 0.224, 0.225]),
        ]
    )


def _build_eval_transform(image_size: int):
    return transforms.Compose(
        [
            transforms.Resize((image_size, image_size)),
            transforms.ToTensor(),
            transforms.Normalize(mean=[0.485, 0.456, 0.406], std=[0.229, 0.224, 0.225]),
        ]
    )


def build_dataloaders(
    dataset_root: Path,
    batch_size: int,
    num_workers: int,
    image_size: int,
    pin_memory: bool,
) -> tuple[DataLoader, DataLoader, dict[str, int]]:
    """构建训练和验证数据加载器，返回 train_loader、val_loader 以及类别名称到索引的映射字典。"""
    train_dataset = CUB200Dataset(
        root=dataset_root,
        split="train",
        transform=_build_train_transform(image_size=image_size),
    )
    val_dataset = CUB200Dataset(
        root=dataset_root,
        split="test",
        transform=_build_eval_transform(image_size=image_size),
        class_to_idx=train_dataset.class_to_idx,
    )

    common_loader_args = {
        "batch_size": batch_size,
        "num_workers": num_workers,
        "pin_memory": pin_memory,
    }
    if num_workers > 0:
        common_loader_args["persistent_workers"] = True

    train_loader = DataLoader(
        train_dataset,
        shuffle=True,
        drop_last=False,
        **common_loader_args,
    )
    val_loader = DataLoader(
        val_dataset,
        shuffle=False,
        drop_last=False,
        **common_loader_args,
    )

    return train_loader, val_loader, train_dataset.class_to_idx
