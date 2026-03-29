from pathlib import Path
from typing import Any

import numpy as np
from PIL import Image
import torch
from torchvision.models.detection import (
    fasterrcnn_mobilenet_v3_large_320_fpn,
    fasterrcnn_resnet50_fpn,
)
from torchvision.models.detection.faster_rcnn import FastRCNNPredictor
from torchvision.transforms import functional as tvf

from src.config import FrameworkKind
from src.models.cropper import CropBox


class PytorchDetectorCropperBackend:
    """基于PyTorch框架的检测模型裁切后端实现。"""

    framework = FrameworkKind.PYTORCH

    @staticmethod
    def _build_detector(model_name: str, num_classes: int) -> torch.nn.Module:
        lower = model_name.lower()
        if "mobilenet" in lower:
            model = fasterrcnn_mobilenet_v3_large_320_fpn(weights=None)
        else:
            model = fasterrcnn_resnet50_fpn(weights=None)

        model_any: Any = model
        in_features = int(model_any.roi_heads.box_predictor.cls_score.in_features)
        model_any.roi_heads.box_predictor = FastRCNNPredictor(
            in_features,
            num_classes=num_classes,
        )
        return model

    def load_detector(self, model_path: Path) -> object:
        suffix = model_path.suffix.lower()
        base = {
            "model_path": str(model_path),
            "framework": self.framework.value,
        }

        if suffix == ".pth":
            payload = torch.load(model_path, map_location="cpu")
            if not isinstance(payload, dict) or "state_dict" not in payload:
                raise ValueError(f"invalid pth checkpoint payload: {model_path}")

            model_name = str(payload.get("model_name", "fasterrcnn_resnet50_fpn"))
            num_classes = int(payload.get("num_classes", 2))
            model = self._build_detector(model_name, num_classes)
            model.load_state_dict(payload["state_dict"])
            model.eval()

            return {
                **base,
                "mode": "eager",
                "model": model,
            }

        if suffix in {".torchscript", ".pt", ".jit"}:
            model = torch.jit.load(str(model_path), map_location="cpu")
            model.eval()
            return {
                **base,
                "mode": "torchscript",
                "model": model,
            }

        if suffix == ".onnx":
            try:
                import onnxruntime as ort
            except ImportError as exc:
                raise ModuleNotFoundError(
                    "onnxruntime is required for onnx crop inference. "
                    "Install it with: uv add onnxruntime"
                ) from exc

            session = ort.InferenceSession(
                str(model_path),
                providers=["CPUExecutionProvider"],
            )
            input_tensor = session.get_inputs()[0]
            return {
                **base,
                "mode": "onnx",
                "session": session,
                "input_name": input_tensor.name,
                "input_shape": input_tensor.shape,
            }

        raise ValueError(
            "unsupported pytorch crop model format: "
            f"{model_path.suffix} (path={model_path})"
        )

    @staticmethod
    def _boxes_to_cropboxes(
        boxes_xyxy: torch.Tensor,
        scores: torch.Tensor,
        width: int,
        height: int,
    ) -> list[CropBox]:
        outputs: list[CropBox] = []
        for box, score in zip(boxes_xyxy.tolist(), scores.tolist()):
            x1, y1, x2, y2 = [float(item) for item in box]
            outputs.append(
                CropBox(
                    x1=max(0.0, min(1.0, x1 / max(width, 1))),
                    y1=max(0.0, min(1.0, y1 / max(height, 1))),
                    x2=max(0.0, min(1.0, x2 / max(width, 1))),
                    y2=max(0.0, min(1.0, y2 / max(height, 1))),
                    score=float(score),
                )
            )
        return outputs

    def _predict_with_torch(
        self,
        image: Image.Image,
        model: Any,
        width: int,
        height: int,
    ) -> list[CropBox]:
        tensor = tvf.to_tensor(image)
        with torch.no_grad():
            outputs = model([tensor])

        if not outputs:
            return []

        first = outputs[0]
        boxes = first.get("boxes", torch.zeros((0, 4), dtype=torch.float32))
        scores = first.get("scores", torch.zeros((0,), dtype=torch.float32))
        return self._boxes_to_cropboxes(
            boxes.detach().cpu(),
            scores.detach().cpu(),
            width,
            height,
        )

    def _predict_with_onnx(
        self,
        image: Image.Image,
        detector_handle: dict[str, Any],
        width: int,
        height: int,
    ) -> list[CropBox]:
        session = detector_handle["session"]
        input_name = str(detector_handle["input_name"])
        input_shape = detector_handle.get("input_shape")

        infer_h, infer_w = height, width
        if isinstance(input_shape, (list, tuple)) and len(input_shape) >= 4:
            maybe_h = input_shape[2]
            maybe_w = input_shape[3]
            if isinstance(maybe_h, int) and maybe_h > 0:
                infer_h = maybe_h
            if isinstance(maybe_w, int) and maybe_w > 0:
                infer_w = maybe_w

        if (infer_w, infer_h) != (width, height):
            resized = image.resize((infer_w, infer_h), Image.Resampling.BILINEAR)
        else:
            resized = image

        array = np.asarray(resized, dtype=np.float32) / 255.0
        array = np.transpose(array, (2, 0, 1))[None, ...]
        boxes, scores, _labels = session.run(None, {input_name: array})

        boxes_tensor = torch.as_tensor(boxes, dtype=torch.float32)
        scores_tensor = torch.as_tensor(scores, dtype=torch.float32)

        if boxes_tensor.ndim == 3:
            boxes_tensor = boxes_tensor[0]
        if scores_tensor.ndim == 2:
            scores_tensor = scores_tensor[0]

        if (infer_w, infer_h) != (width, height):
            scale_x = float(width) / float(infer_w)
            scale_y = float(height) / float(infer_h)
            boxes_tensor[:, 0] *= scale_x
            boxes_tensor[:, 2] *= scale_x
            boxes_tensor[:, 1] *= scale_y
            boxes_tensor[:, 3] *= scale_y

        return self._boxes_to_cropboxes(boxes_tensor, scores_tensor, width, height)

    def detect_boxes(
        self,
        image: Image.Image,
        detector_handle: object,
    ) -> list[CropBox]:
        handle = detector_handle if isinstance(detector_handle, dict) else {}
        width, height = image.size
        if width < 8 or height < 8:
            return []

        mode = str(handle.get("mode", ""))
        if mode in {"eager", "torchscript"}:
            model = handle.get("model")
            if model is None:
                raise ValueError("invalid pytorch detector handle: missing model")
            return self._predict_with_torch(image, model, width, height)

        if mode == "onnx":
            return self._predict_with_onnx(image, handle, width, height)

        raise ValueError(f"invalid pytorch detector handle mode: {mode}")
