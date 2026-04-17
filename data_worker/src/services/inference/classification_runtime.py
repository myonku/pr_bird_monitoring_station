from typing import Any, cast

from PIL import Image

from src.models.inference.workflow import ClassificationHit
from src.services.inference.runtime_common import normalize_input_size, safe_label


class ClassificationRuntime:
    """提供分类推理功能的运行时组件，支持 YOLO / PyTorch / ONNX。"""

    def _classification_topk_from_probs(
        self,
        probs: list[float],
        labels: list[str],
        topk: int,
    ) -> list[ClassificationHit]:
        indexed = sorted(
            enumerate(probs),
            key=lambda item: float(item[1]),
            reverse=True,
        )
        limited = indexed[: max(1, topk)]
        return [
            ClassificationHit(
                label=safe_label(labels, int(index), "cls"),
                confidence=float(score),
            )
            for index, score in limited
        ]

    def _classify_with_yolo(
        self,
        image: Image.Image,
        handle: dict[str, Any],
        labels: list[str],
        topk: int,
    ) -> list[ClassificationHit]:
        model = handle.get("model")
        if model is None:
            raise ValueError("missing yolo classification model handle")

        infer_w, infer_h = normalize_input_size(
            handle.get("input_size"),
            default=(224, 224),
        )
        imgsz = int(max(infer_w, infer_h))

        results = model.predict(source=image, imgsz=imgsz, verbose=False)
        if not results:
            return []

        probs_obj = getattr(results[0], "probs", None)
        if probs_obj is None:
            return []

        data = getattr(probs_obj, "data", None)
        if data is None:
            return []

        probs = [float(item) for item in data.detach().cpu().tolist()]
        return self._classification_topk_from_probs(probs, labels, topk)

    def _classify_with_pytorch_onnx(
        self,
        image: Image.Image,
        handle: dict[str, Any],
        labels: list[str],
        topk: int,
    ) -> list[ClassificationHit]:
        try:
            import numpy as np
        except ImportError as exc:
            raise ModuleNotFoundError(
                "numpy is required for pytorch onnx classification inference"
            ) from exc

        session = handle.get("session")
        input_name = str(handle.get("input_name", ""))
        input_shape = handle.get("input_shape")
        if session is None or not input_name:
            raise ValueError("invalid pytorch onnx classification handle")

        infer_h, infer_w = 224, 224
        if isinstance(input_shape, (tuple, list)) and len(input_shape) >= 4:
            maybe_h = input_shape[2]
            maybe_w = input_shape[3]
            if isinstance(maybe_h, int) and maybe_h > 0:
                infer_h = maybe_h
            if isinstance(maybe_w, int) and maybe_w > 0:
                infer_w = maybe_w

        resized = image.resize((infer_w, infer_h), Image.Resampling.BILINEAR)
        array = np.asarray(resized, dtype=np.float32) / 255.0

        mean = np.asarray([0.485, 0.456, 0.406], dtype=np.float32)
        std = np.asarray([0.229, 0.224, 0.225], dtype=np.float32)
        array = (array - mean) / std

        array = np.transpose(array, (2, 0, 1))[None, ...]
        outputs = session.run(None, {input_name: array})
        if not outputs:
            return []

        logits = outputs[0]
        logits = logits[0] if getattr(logits, "ndim", 0) > 1 else logits
        logits = logits.astype(np.float32)
        logits = logits - np.max(logits)
        exp_logits = np.exp(logits)
        probs = (exp_logits / np.maximum(np.sum(exp_logits), 1e-12)).tolist()
        return self._classification_topk_from_probs(probs, labels, topk)

    def _classify_with_pytorch(
        self,
        image: Image.Image,
        handle: dict[str, Any],
        labels: list[str],
        topk: int,
    ) -> list[ClassificationHit]:
        mode = str(handle.get("mode", "")).lower()
        if mode == "onnx":
            return self._classify_with_pytorch_onnx(
                image=image,
                handle=handle,
                labels=labels,
                topk=topk,
            )

        try:
            import torch
            from torchvision import transforms as tv_transforms
        except ImportError as exc:
            raise ModuleNotFoundError(
                "torch/torchvision are required for pytorch classification inference"
            ) from exc

        model = handle.get("model")
        if model is None:
            raise ValueError("missing pytorch classification model handle")

        device = torch.device(str(handle.get("device", "cpu")))
        width, height = normalize_input_size(
            handle.get("input_size"),
            default=(224, 224),
        )

        transform = tv_transforms.Compose(
            [
                tv_transforms.Resize((height, width)),
                tv_transforms.ToTensor(),
                tv_transforms.Normalize(
                    mean=(0.485, 0.456, 0.406),
                    std=(0.229, 0.224, 0.225),
                ),
            ]
        )
        transformed = cast(Any, transform(image))
        tensor = transformed.unsqueeze(0).to(device)

        with torch.no_grad():
            logits = model(tensor)

        if isinstance(logits, (tuple, list)):
            logits = logits[0]
        if logits.ndim == 1:
            logits = logits.unsqueeze(0)

        probs = torch.softmax(logits, dim=1)[0]
        k = min(max(1, topk), int(probs.shape[0]))
        values, indices = torch.topk(probs, k=k)
        return [
            ClassificationHit(
                label=safe_label(labels, int(index.item()), "cls"),
                confidence=float(value.item()),
            )
            for value, index in zip(values.cpu(), indices.cpu())
        ]

    def run(
        self,
        image: Image.Image,
        handle: dict[str, Any],
        labels: list[str],
        topk: int,
    ) -> list[ClassificationHit]:
        engine = str(handle.get("engine", "")).lower()
        if engine == "yolo":
            return self._classify_with_yolo(
                image=image,
                handle=handle,
                labels=labels,
                topk=topk,
            )
        if engine == "pytorch":
            return self._classify_with_pytorch(
                image=image,
                handle=handle,
                labels=labels,
                topk=topk,
            )

        raise ValueError(
            f"unsupported classification engine in handle: {engine or 'unknown'}"
        )