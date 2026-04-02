from typing import Any

from PIL import Image

from src.models.workflow.workflow import DetectionBox
from src.reasoner.runtime.runtime_common import normalize_input_size, safe_label


class DetectionRuntime:
    """提供检测推理功能的运行时组件，支持多种引擎（如 PyTorch、ONNX Runtime、YOLO 等）。"""

    def _detect_with_yolo(
        self,
        image: Image.Image,
        handle: dict[str, Any],
        labels: list[str],
        score_threshold: float,
    ) -> list[DetectionBox]:
        model = handle.get("model")
        if model is None:
            raise ValueError("missing yolo detection model handle")

        infer_w, infer_h = normalize_input_size(
            handle.get("input_size"),
            default=(640, 640),
        )
        imgsz = int(max(infer_w, infer_h))

        iou_threshold = float(handle.get("nms_iou_threshold", 0.45))
        results = model.predict(
            source=image,
            conf=score_threshold,
            iou=iou_threshold,
            imgsz=imgsz,
            verbose=False,
        )
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
            width, height = image.size
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
        cls_tensor = getattr(boxes, "cls", None)
        if conf_tensor is None or cls_tensor is None:
            return []

        scores = conf_tensor.detach().cpu().tolist()
        cls_ids = [int(item) for item in cls_tensor.detach().cpu().tolist()]

        outputs: list[DetectionBox] = []
        for coords, score, cls_id in zip(coords_list, scores, cls_ids):
            score_value = float(score)
            if score_value < score_threshold:
                continue
            x1, y1, x2, y2 = coords
            outputs.append(
                DetectionBox(
                    label=safe_label(labels, cls_id, "det"),
                    confidence=score_value,
                    x1=float(max(0.0, min(1.0, x1))),
                    y1=float(max(0.0, min(1.0, y1))),
                    x2=float(max(0.0, min(1.0, x2))),
                    y2=float(max(0.0, min(1.0, y2))),
                )
            )
        return outputs

    def _detect_with_pytorch_onnx(
        self,
        image: Image.Image,
        handle: dict[str, Any],
        labels: list[str],
        score_threshold: float,
    ) -> list[DetectionBox]:
        try:
            import numpy as np
        except ImportError as exc:
            raise ModuleNotFoundError(
                "numpy is required for pytorch onnx detection inference"
            ) from exc

        session = handle.get("session")
        input_name = str(handle.get("input_name", ""))
        input_shape = handle.get("input_shape")
        if session is None or not input_name:
            raise ValueError("invalid pytorch onnx detection handle")

        width, height = image.size
        infer_h, infer_w = height, width
        if isinstance(input_shape, (tuple, list)) and len(input_shape) >= 4:
            maybe_h = input_shape[2]
            maybe_w = input_shape[3]
            if isinstance(maybe_h, int) and maybe_h > 0:
                infer_h = maybe_h
            if isinstance(maybe_w, int) and maybe_w > 0:
                infer_w = maybe_w

        resized = (
            image.resize((infer_w, infer_h), Image.Resampling.BILINEAR)
            if (infer_w, infer_h) != (width, height)
            else image
        )

        array = np.asarray(resized, dtype=np.float32) / 255.0
        array = np.transpose(array, (2, 0, 1))[None, ...]
        outputs = session.run(None, {input_name: array})
        if len(outputs) < 3:
            return []

        boxes, scores, cls_ids = outputs[0], outputs[1], outputs[2]
        boxes = boxes[0] if getattr(boxes, "ndim", 0) == 3 else boxes
        scores = scores[0] if getattr(scores, "ndim", 0) == 2 else scores
        cls_ids = cls_ids[0] if getattr(cls_ids, "ndim", 0) == 2 else cls_ids

        if (infer_w, infer_h) != (width, height):
            scale_x = float(width) / float(infer_w)
            scale_y = float(height) / float(infer_h)
            boxes[:, 0] *= scale_x
            boxes[:, 2] *= scale_x
            boxes[:, 1] *= scale_y
            boxes[:, 3] *= scale_y

        outputs_boxes: list[DetectionBox] = []
        for box, score, cls_id in zip(
            boxes.tolist(), scores.tolist(), cls_ids.tolist()
        ):
            score_value = float(score)
            if score_value < score_threshold:
                continue
            x1, y1, x2, y2 = [float(item) for item in box]
            outputs_boxes.append(
                DetectionBox(
                    label=safe_label(labels, int(cls_id), "det"),
                    confidence=score_value,
                    x1=max(0.0, min(1.0, x1 / max(width, 1))),
                    y1=max(0.0, min(1.0, y1 / max(height, 1))),
                    x2=max(0.0, min(1.0, x2 / max(width, 1))),
                    y2=max(0.0, min(1.0, y2 / max(height, 1))),
                )
            )
        return outputs_boxes

    def _detect_with_pytorch(
        self,
        image: Image.Image,
        handle: dict[str, Any],
        labels: list[str],
        score_threshold: float,
    ) -> list[DetectionBox]:
        mode = str(handle.get("mode", "")).lower()
        if mode == "onnx":
            return self._detect_with_pytorch_onnx(
                image=image,
                handle=handle,
                labels=labels,
                score_threshold=score_threshold,
            )

        try:
            import torch
            from torchvision.transforms import functional as tvf
        except ImportError as exc:
            raise ModuleNotFoundError(
                "torch/torchvision are required for pytorch detection inference"
            ) from exc

        model = handle.get("model")
        if model is None:
            raise ValueError("missing pytorch detection model handle")

        device = torch.device(str(handle.get("device", "cpu")))
        tensor = tvf.to_tensor(image).to(device)
        with torch.no_grad():
            outputs = model([tensor])

        first = outputs[0] if isinstance(outputs, list) else outputs
        boxes = first.get(
            "boxes", torch.zeros((0, 4), dtype=torch.float32, device=device)
        )
        scores = first.get(
            "scores", torch.zeros((0,), dtype=torch.float32, device=device)
        )
        cls_ids = first.get(
            "labels",
            torch.zeros((0,), dtype=torch.int64, device=device),
        )

        width, height = image.size
        out_boxes: list[DetectionBox] = []
        for box, score, cls_id in zip(
            boxes.detach().cpu().tolist(),
            scores.detach().cpu().tolist(),
            cls_ids.detach().cpu().tolist(),
        ):
            score_value = float(score)
            if score_value < score_threshold:
                continue
            x1, y1, x2, y2 = [float(item) for item in box]
            out_boxes.append(
                DetectionBox(
                    label=safe_label(labels, int(cls_id), "det"),
                    confidence=score_value,
                    x1=max(0.0, min(1.0, x1 / max(width, 1))),
                    y1=max(0.0, min(1.0, y1 / max(height, 1))),
                    x2=max(0.0, min(1.0, x2 / max(width, 1))),
                    y2=max(0.0, min(1.0, y2 / max(height, 1))),
                )
            )
        return out_boxes

    def run(
        self,
        image: Image.Image,
        handle: dict[str, Any],
        labels: list[str],
        score_threshold: float,
    ) -> list[DetectionBox]:
        engine = str(handle.get("engine", "")).lower()
        if engine == "yolo":
            return self._detect_with_yolo(
                image=image,
                handle=handle,
                labels=labels,
                score_threshold=score_threshold,
            )
        if engine == "pytorch":
            return self._detect_with_pytorch(
                image=image,
                handle=handle,
                labels=labels,
                score_threshold=score_threshold,
            )

        raise ValueError(
            f"unsupported detection engine in handle: {engine or 'unknown'}"
        )
