from pathlib import Path

from PIL import Image
from src.config import FrameworkKind
from src.models.cropper import CropBox


class YoloDetectorCropperBackend:
    """基于YOLO框架的检测模型裁切后端实现。"""
    framework = FrameworkKind.YOLO

    def load_detector(self, model_path: Path) -> object:
        try:
            from ultralytics import YOLO
        except ImportError as exc:
            raise ModuleNotFoundError(
                "ultralytics is required for YOLO cropper backend. "
                "Install it with: uv add ultralytics"
            ) from exc

        model = YOLO(str(model_path))
        return {
            "model_path": str(model_path),
            "framework": self.framework.value,
            "model": model,
        }

    def detect_boxes(
        self, image: Image.Image, detector_handle: object
    ) -> list[CropBox]:
        width, height = image.size
        if width < 8 or height < 8:
            return []

        handle = detector_handle if isinstance(detector_handle, dict) else {}
        model = handle.get("model")
        if model is None:
            raise ValueError("invalid yolo detector handle: missing model")

        results = model.predict(source=image, verbose=False)
        if not results:
            return []

        boxes = getattr(results[0], "boxes", None)
        if boxes is None:
            return []

        xyxyn_tensor = getattr(boxes, "xyxyn", None)
        if xyxyn_tensor is not None:
            coords_list = xyxyn_tensor.detach().cpu().tolist()
        else:
            xyxy_tensor = getattr(boxes, "xyxy", None)
            if xyxy_tensor is None:
                return []

            xyxy_list = xyxy_tensor.detach().cpu().tolist()
            coords_list = [
                [
                    float(x1) / max(width, 1),
                    float(y1) / max(height, 1),
                    float(x2) / max(width, 1),
                    float(y2) / max(height, 1),
                ]
                for x1, y1, x2, y2 in xyxy_list
            ]

        conf_tensor = getattr(boxes, "conf", None)
        if conf_tensor is None:
            return []
        scores = conf_tensor.detach().cpu().tolist()
        if not coords_list or not scores:
            return []

        outputs: list[CropBox] = []
        for coords, score in zip(coords_list, scores):
            x1, y1, x2, y2 = coords
            outputs.append(
                CropBox(
                    x1=float(max(0.0, min(1.0, x1))),
                    y1=float(max(0.0, min(1.0, y1))),
                    x2=float(max(0.0, min(1.0, x2))),
                    y2=float(max(0.0, min(1.0, y2))),
                    score=float(score),
                )
            )

        return outputs
