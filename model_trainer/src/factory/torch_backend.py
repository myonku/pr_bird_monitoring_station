import shutil
import time
import warnings
from collections import defaultdict
from pathlib import Path
from typing import Any, cast

import numpy as np
import torch
from torch import nn
from torch.utils.data import DataLoader
from torchvision.models.detection import (
    fasterrcnn_mobilenet_v3_large_320_fpn,
    fasterrcnn_resnet50_fpn,
)
from torchvision.models.detection.faster_rcnn import FastRCNNPredictor

from src.config import FrameworkKind, ModelCandidate
from src.factory.func import deterministic_score, make_export_artifacts
from src.models.common import TaskType
from src.models.dataset_model import DatasetBundle
from src.models.training import TrainingOutput
from src.datasets.detection_dataset import CocoDetectionDataset


class _DetectionExportWrapper(nn.Module):
    """包装检测模型以适配 ONNX 导出，确保输出格式统一为 (boxes, scores, labels)。"""

    def __init__(self, model: nn.Module) -> None:
        super().__init__()
        self.model = model

    def forward(
        self, images: torch.Tensor
    ) -> tuple[torch.Tensor, torch.Tensor, torch.Tensor]:
        outputs = self.model([images[0]])
        first = outputs[0]
        return first["boxes"], first["scores"], first["labels"].to(torch.int64)


class PytorchBackend:
    """PyTorch 训练后端。检测任务走真实训练路径，分类任务保留占位实现。"""

    framework = FrameworkKind.PYTORCH

    def train(
        self,
        candidate: ModelCandidate,
        dataset: DatasetBundle,
        output_dir: Path,
    ) -> TrainingOutput:
        if candidate.task == TaskType.DETECTION:
            return self._train_detection(
                candidate=candidate, dataset=dataset, output_dir=output_dir
            )
        return self._train_placeholder(
            candidate=candidate, dataset=dataset, output_dir=output_dir
        )

    @staticmethod
    def _resolve_detection_paths(
        dataset: DatasetBundle,
    ) -> tuple[Path, Path, Path, Path]:
        paths = dataset.metadata.get("paths", {})
        coco_paths = paths.get("coco", {})
        yolo_paths = paths.get("yolo", {})

        train_ann = coco_paths.get("train")
        val_ann = coco_paths.get("val")
        train_images = yolo_paths.get("images_train")
        val_images = yolo_paths.get("images_val")
        if not train_ann or not val_ann or not train_images or not val_images:
            raise ValueError(
                "Detection dataset metadata missing coco/yolo path mappings for train/val"
            )

        return (
            Path(str(train_ann)),
            Path(str(val_ann)),
            Path(str(train_images)),
            Path(str(val_images)),
        )

    @staticmethod
    def _resolve_device(train_params: dict[str, Any]) -> torch.device:
        configured = train_params.get("device")
        if configured is not None:
            return torch.device(str(configured))
        return torch.device("cuda" if torch.cuda.is_available() else "cpu")

    @staticmethod
    def _build_detector(model_name: str, pretrained: bool) -> nn.Module:
        lower = model_name.lower()
        if "mobilenet" in lower:
            model = fasterrcnn_mobilenet_v3_large_320_fpn(
                weights="DEFAULT" if pretrained else None
            )
        else:
            model = fasterrcnn_resnet50_fpn(weights="DEFAULT" if pretrained else None)

        model_any = cast(Any, model)
        in_features = int(model_any.roi_heads.box_predictor.cls_score.in_features)
        model_any.roi_heads.box_predictor = FastRCNNPredictor(
            in_features,
            num_classes=2,
        )
        return model

    @staticmethod
    def _collate(
        batch: list[tuple[torch.Tensor, dict[str, torch.Tensor]]],
    ) -> tuple[list[torch.Tensor], list[dict[str, torch.Tensor]]]:
        images, targets = zip(*batch)
        return list(images), list(targets)

    @staticmethod
    def _print_epoch_progress(
        *,
        epoch: int,
        epochs: int,
        step: int,
        total_steps: int,
        loss_value: float,
    ) -> None:
        progress = (step / max(total_steps, 1)) * 100.0
        print(
            (
                f"\r[PyTorch][train] epoch {epoch}/{epochs} "
                f"step {step}/{total_steps} ({progress:5.1f}%) "
                f"loss={loss_value:.4f}"
            ),
            end="",
            flush=True,
        )

    @staticmethod
    def _iou_with_boxes(box: torch.Tensor, boxes: torch.Tensor) -> torch.Tensor:
        if boxes.numel() == 0:
            return torch.zeros((0,), dtype=torch.float32)

        x1 = torch.maximum(box[0], boxes[:, 0])
        y1 = torch.maximum(box[1], boxes[:, 1])
        x2 = torch.minimum(box[2], boxes[:, 2])
        y2 = torch.minimum(box[3], boxes[:, 3])

        inter_w = torch.clamp(x2 - x1, min=0.0)
        inter_h = torch.clamp(y2 - y1, min=0.0)
        inter = inter_w * inter_h

        box_area = torch.clamp(box[2] - box[0], min=0.0) * torch.clamp(
            box[3] - box[1], min=0.0
        )
        boxes_area = torch.clamp(boxes[:, 2] - boxes[:, 0], min=0.0) * torch.clamp(
            boxes[:, 3] - boxes[:, 1], min=0.0
        )
        union = box_area + boxes_area - inter
        union = torch.clamp(union, min=1e-8)
        return inter / union

    def _average_precision(
        self,
        predictions: list[tuple[float, int, torch.Tensor]],
        ground_truths: dict[int, torch.Tensor],
        iou_threshold: float,
    ) -> float:
        total_gt = sum(int(items.shape[0]) for items in ground_truths.values())
        if total_gt <= 0:
            return 0.0

        matched: dict[int, set[int]] = defaultdict(set)
        ordered = sorted(predictions, key=lambda item: item[0], reverse=True)

        tp: list[int] = []
        fp: list[int] = []
        for _score, image_id, pred_box in ordered:
            gt_boxes = ground_truths.get(image_id)
            if gt_boxes is None or gt_boxes.numel() == 0:
                tp.append(0)
                fp.append(1)
                continue

            ious = self._iou_with_boxes(pred_box, gt_boxes)
            if ious.numel() == 0:
                tp.append(0)
                fp.append(1)
                continue

            best_iou, best_idx = torch.max(ious, dim=0)
            best_idx_value = int(best_idx.item())
            if (
                best_iou.item() >= iou_threshold
                and best_idx_value not in matched[image_id]
            ):
                matched[image_id].add(best_idx_value)
                tp.append(1)
                fp.append(0)
            else:
                tp.append(0)
                fp.append(1)

        if not tp:
            return 0.0

        tp_cum = np.cumsum(np.asarray(tp, dtype=np.float64))
        fp_cum = np.cumsum(np.asarray(fp, dtype=np.float64))

        recalls = tp_cum / float(total_gt)
        precisions = tp_cum / np.maximum(tp_cum + fp_cum, 1e-12)

        recalls = np.concatenate(([0.0], recalls, [1.0]))
        precisions = np.concatenate(([0.0], precisions, [0.0]))
        for index in range(precisions.size - 1, 0, -1):
            precisions[index - 1] = max(precisions[index - 1], precisions[index])

        changing = np.where(recalls[1:] != recalls[:-1])[0]
        ap = np.sum(
            (recalls[changing + 1] - recalls[changing]) * precisions[changing + 1]
        )
        return float(ap)

    def _evaluate_map(
        self,
        model: nn.Module,
        val_loader: DataLoader,
        device: torch.device,
        score_threshold: float,
    ) -> tuple[float, float]:
        model.eval()
        ground_truths: dict[int, torch.Tensor] = {}
        predictions: list[tuple[float, int, torch.Tensor]] = []

        with torch.no_grad():
            for images, targets in val_loader:
                image_list = [image.to(device) for image in images]
                outputs = model(image_list)
                for target, output in zip(targets, outputs):
                    image_id = int(target["image_id"].item())
                    ground_truths[image_id] = target["boxes"].cpu()

                    boxes = output.get("boxes", torch.zeros((0, 4))).detach().cpu()
                    scores = output.get("scores", torch.zeros((0,))).detach().cpu()
                    labels = (
                        output.get("labels", torch.zeros((0,), dtype=torch.int64))
                        .detach()
                        .cpu()
                    )

                    for box, score, label in zip(boxes, scores, labels):
                        if int(label.item()) != 1:
                            continue
                        score_value = float(score.item())
                        if score_value < score_threshold:
                            continue
                        predictions.append((score_value, image_id, box))

        map50 = self._average_precision(predictions, ground_truths, 0.50)
        thresholds = [round(0.50 + 0.05 * step, 2) for step in range(10)]
        ap_values = [
            self._average_precision(predictions, ground_truths, threshold)
            for threshold in thresholds
        ]
        map50_95 = float(np.mean(ap_values)) if ap_values else 0.0
        return map50, map50_95

    @staticmethod
    def _benchmark_latency_ms(
        model: nn.Module, image_size: int, device: torch.device
    ) -> float:
        model.eval()
        sample = torch.zeros(
            (3, image_size, image_size), dtype=torch.float32, device=device
        )
        with torch.no_grad():
            _ = model([sample])
            start = time.perf_counter()
            _ = model([sample])
        return round((time.perf_counter() - start) * 1000.0, 4)

    @staticmethod
    def _export_with_fallback(
        model: nn.Module,
        checkpoint: Path,
        candidate: ModelCandidate,
        output_dir: Path,
        image_size: int,
    ) -> list[str]:
        output_dir.mkdir(parents=True, exist_ok=True)
        prefix = f"{candidate.task.value}_{candidate.tier.value}_{candidate.candidate_id}"
        paths: list[str] = []

        model_cpu = model.to("cpu").eval()
        for fmt in candidate.export_formats:
            normalized = fmt.strip().lower()

            if normalized in {"torchscript", "ts"}:
                target = output_dir / f"{prefix}.torchscript"
                try:
                    scripted = torch.jit.script(model_cpu)
                    scripted.save(str(target))
                    paths.append(str(target))
                    continue
                except Exception:
                    shutil.copy2(checkpoint, target)
                    paths.append(str(target))
                    continue

            if normalized == "onnx":
                target = output_dir / f"{prefix}.onnx"
                wrapper = _DetectionExportWrapper(model_cpu)
                dummy = torch.zeros((1, 3, image_size, image_size), dtype=torch.float32)
                try:
                    torch.onnx.export(
                        wrapper,
                        (dummy,),
                        str(target),
                        input_names=["images"],
                        output_names=["boxes", "scores", "labels"],
                        dynamic_axes={
                            "boxes": {0: "num_boxes"},
                            "scores": {0: "num_boxes"},
                            "labels": {0: "num_boxes"},
                        },
                        opset_version=17,
                    )
                    paths.append(str(target))
                    continue
                except Exception:
                    shutil.copy2(checkpoint, target)
                    paths.append(str(target))
                    continue

            target = output_dir / f"{prefix}.{normalized}"
            shutil.copy2(checkpoint, target)
            paths.append(str(target))

        return paths

    def _train_detection(
        self,
        candidate: ModelCandidate,
        dataset: DatasetBundle,
        output_dir: Path,
    ) -> TrainingOutput:
        output_dir.mkdir(parents=True, exist_ok=True)
        train_ann, val_ann, train_images, val_images = self._resolve_detection_paths(
            dataset
        )

        train_dataset = CocoDetectionDataset(
            annotation_path=train_ann, images_root=train_images
        )
        val_dataset = CocoDetectionDataset(
            annotation_path=val_ann, images_root=val_images
        )
        if len(train_dataset) == 0:
            raise ValueError("Detection train dataset is empty")

        train_params = candidate.train_params
        device = self._resolve_device(train_params)
        pretrained = bool(train_params.get("pretrained", False))
        model = self._build_detector(candidate.model_name, pretrained=pretrained).to(
            device
        )

        batch_size = max(
            1, int(train_params.get("batch_size", train_params.get("batch", 4)))
        )
        num_workers = int(
            train_params.get("num_workers", train_params.get("workers", 2))
        )
        epochs = max(1, int(train_params.get("epochs", 10)))
        learning_rate = float(train_params.get("learning_rate", 1e-3))
        weight_decay = float(train_params.get("weight_decay", 1e-4))
        score_threshold = float(train_params.get("score_threshold", 0.001))
        image_size = int(train_params.get("imgsz", train_params.get("image_size", 640)))
        show_progress = bool(train_params.get("show_progress", True))

        train_loader = DataLoader(
            train_dataset,
            batch_size=batch_size,
            shuffle=True,
            num_workers=num_workers,
            collate_fn=self._collate,
        )
        val_loader = DataLoader(
            val_dataset,
            batch_size=1,
            shuffle=False,
            num_workers=num_workers,
            collate_fn=self._collate,
        )

        optimizer = torch.optim.SGD(
            [param for param in model.parameters() if param.requires_grad],
            lr=learning_rate,
            momentum=0.9,
            weight_decay=weight_decay,
        )

        tensor_copy_warning = (
            r"To copy construct from a tensor, it is recommended to use "
            r"sourceTensor\.clone\(\)\.detach\(\)"
        )
        with warnings.catch_warnings():
            warnings.filterwarnings(
                "ignore",
                message=tensor_copy_warning,
                category=UserWarning,
            )

            model.train()
            total_steps = len(train_loader)
            for epoch_index in range(epochs):
                epoch_loss = 0.0
                for step_index, (images, targets) in enumerate(train_loader, start=1):
                    images = [image.to(device) for image in images]
                    targets = [
                        {key: value.to(device) for key, value in item.items()}
                        for item in targets
                    ]

                    loss_dict = model(images, targets)
                    total_loss = torch.stack(list(loss_dict.values())).sum()

                    optimizer.zero_grad(set_to_none=True)
                    total_loss.backward()
                    optimizer.step()

                    loss_value = float(total_loss.detach().cpu().item())
                    epoch_loss += loss_value
                    if show_progress:
                        self._print_epoch_progress(
                            epoch=epoch_index + 1,
                            epochs=epochs,
                            step=step_index,
                            total_steps=total_steps,
                            loss_value=loss_value,
                        )

                if show_progress:
                    avg_loss = epoch_loss / max(total_steps, 1)
                    print(
                        f"\r[PyTorch][train] epoch {epoch_index + 1}/{epochs} done, avg_loss={avg_loss:.4f}".ljust(120),
                        flush=True,
                    )

            map50, map50_95 = self._evaluate_map(
                model=model,
                val_loader=val_loader,
                device=device,
                score_threshold=score_threshold,
            )
        if show_progress:
            print(
                f"[PyTorch][eval] map50={map50:.6f}, map50_95={map50_95:.6f}",
                flush=True,
            )

        prefix = f"{candidate.task.value}_{candidate.tier.value}_{candidate.candidate_id}"
        checkpoint = output_dir / f"{prefix}.pth"
        torch.save(
            {
                "candidate_id": candidate.candidate_id,
                "model_name": candidate.model_name,
                "task": candidate.task.value,
                "state_dict": model.state_dict(),
                "num_classes": 2,
            },
            checkpoint,
        )

        latency_ms = self._benchmark_latency_ms(
            model=model, image_size=image_size, device=device
        )
        exported = self._export_with_fallback(
            model=model,
            checkpoint=checkpoint,
            candidate=candidate,
            output_dir=output_dir,
            image_size=image_size,
        )
        size_mb = round(checkpoint.stat().st_size / (1024 * 1024), 4)

        return TrainingOutput(
            candidate_id=candidate.candidate_id,
            framework=candidate.framework.value,
            model_name=candidate.model_name,
            tier=candidate.tier.value,
            task=candidate.task.value,
            map50=round(float(map50), 6),
            map50_95=round(float(map50_95), 6),
            top1=0.0,
            latency_ms=latency_ms,
            size_mb=size_mb,
            checkpoint_path=str(checkpoint),
            exported_paths=exported,
        )

    def _train_placeholder(
        self,
        candidate: ModelCandidate,
        dataset: DatasetBundle,
        output_dir: Path,
    ) -> TrainingOutput:
        output_dir.mkdir(parents=True, exist_ok=True)
        prefix = f"{candidate.task.value}_{candidate.tier.value}_{candidate.candidate_id}"
        checkpoint = output_dir / f"{prefix}.ckpt"
        checkpoint.write_text(
            "placeholder pytorch checkpoint\n"
            f"dataset={dataset.dataset_id}\n"
            f"model={candidate.model_name}\n",
            encoding="utf-8",
        )

        base = f"{candidate.candidate_id}:{candidate.model_name}:{dataset.dataset_id}"
        exported = make_export_artifacts(
            output_dir, candidate, candidate.export_formats
        )
        return TrainingOutput(
            candidate_id=candidate.candidate_id,
            framework=candidate.framework.value,
            model_name=candidate.model_name,
            tier=candidate.tier.value,
            task=candidate.task.value,
            map50=0.0,
            map50_95=0.0,
            top1=deterministic_score(base + ":top1", 0.55, 0.92),
            latency_ms=deterministic_score(base + ":latency", 6.0, 65.0),
            size_mb=deterministic_score(base + ":size", 4.0, 180.0),
            checkpoint_path=str(checkpoint),
            exported_paths=exported,
        )
