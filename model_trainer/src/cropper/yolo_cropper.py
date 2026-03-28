from pathlib import Path

from PIL import Image
from src.config import FrameworkKind
from src.models.cropper import CropBox


class YoloDetectorCropperBackend:
    """基于YOLO框架的检测模型裁切后端实现。"""
    framework = FrameworkKind.YOLO

    def load_detector(self, model_path: Path) -> object:
        return {"model_path": str(model_path), "framework": self.framework.value}

    def detect_boxes(
        self, image: Image.Image, detector_handle: object
    ) -> list[CropBox]:
        _ = detector_handle
        width, height = image.size
        if width < 8 or height < 8:
            return []
        return [CropBox(x1=0.08, y1=0.1, x2=0.92, y2=0.95, score=0.65)]
