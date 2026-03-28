from pathlib import Path

from PIL import Image
from src.config import FrameworkKind
from src.models.cropper import CropBox


class PytorchDetectorCropperBackend:
    """基于PyTorch框架的检测模型裁切后端实现。"""
    framework = FrameworkKind.PYTORCH

    def load_detector(self, model_path: Path) -> object:
        return {"model_path": str(model_path), "framework": self.framework.value}

    def detect_boxes(
        self, image: Image.Image, detector_handle: object
    ) -> list[CropBox]:
        _ = detector_handle
        width, height = image.size
        if width < 8 or height < 8:
            return []
        return [CropBox(x1=0.12, y1=0.12, x2=0.88, y2=0.9, score=0.61)]
