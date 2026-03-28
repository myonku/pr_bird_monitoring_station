from typing import Any

from src.factory.torch_backend import PytorchBackend
from src.factory.yolo_backend import YoloBackend
from src.models.common import FrameworkKind


def build_backend_registry() -> dict[FrameworkKind, Any]:
    """构建训练后端注册表，映射每个框架到其对应的训练实现类实例。"""
    return {
        FrameworkKind.YOLO: YoloBackend(),
        FrameworkKind.PYTORCH: PytorchBackend(),
    }
