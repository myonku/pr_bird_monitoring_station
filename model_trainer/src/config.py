from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Literal


@dataclass(slots=True)
class TrainConfig:
    """训练配置类，用于存储模型训练所需的所有参数。"""
    model_name: Literal["mobilenet_v3", "efficientnet_lite"]
    dataset_root: Path
    epochs: int = 20
    batch_size: int = 32
    learning_rate: float = 1e-3
    weight_decay: float = 1e-4
    num_workers: int = 4
    image_size: int = 224
    pretrained: bool = True
    device: str = "cuda"
    use_amp: bool = True
    seed: int = 42
    run_name: str | None = None
    models_dir: Path = Path("output_models")
    logs_dir: Path = Path("logs")

    def to_dict(self) -> dict:
        payload = asdict(self)
        payload["dataset_root"] = str(self.dataset_root)
        payload["models_dir"] = str(self.models_dir)
        payload["logs_dir"] = str(self.logs_dir)
        return payload
