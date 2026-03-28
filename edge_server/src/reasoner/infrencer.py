from __future__ import annotations

import io
import time

from PIL import Image

from src.interface import IInferenceModule, IModelBundleLoader
from src.models.models import (
    ClassificationHit,
    ClassificationResult,
    DetectionBox,
    DetectionResult,
    EdgeModelContract,
    ImagePayload,
    LoadedModelBundle,
    TwoStageInferenceResult,
)


class LocalModelBundleLoader(IModelBundleLoader):
    """一次加载检测和分类模型，向上层暴露统一模型句柄。"""

    def __init__(self) -> None:
        self._bundle: LoadedModelBundle | None = None

    def load(self, contract: EdgeModelContract) -> LoadedModelBundle:
        if contract.detection.task != "detection":
            raise ValueError("contract.detection.task must be detection")
        if contract.classification.task != "classification":
            raise ValueError("contract.classification.task must be classification")

        detection_handle = {
            "artifact_path": contract.detection.artifact_path,
            "format": contract.detection.format,
        }
        classification_handle = {
            "artifact_path": contract.classification.artifact_path,
            "format": contract.classification.format,
        }

        self._bundle = LoadedModelBundle(
            contract=contract,
            detection_handle=detection_handle,
            classification_handle=classification_handle,
        )
        return self._bundle

    def current_bundle(self) -> LoadedModelBundle:
        if self._bundle is None:
            raise RuntimeError("model bundle not loaded")
        return self._bundle

    def current_contract(self) -> EdgeModelContract:
        return self.current_bundle().contract


class TwoStageInferenceModule(IInferenceModule):
    """两阶段推理：检测 -> 分类；检测失败或无目标时提前退出。"""

    def detect(self, image: ImagePayload, models: LoadedModelBundle) -> DetectionResult:
        start = time.time()

        if not image.bytes_data:
            return DetectionResult(
                success=False,
                boxes=[],
                latency_ms=int((time.time() - start) * 1000),
                reason="empty_image",
            )

        # 这里是占位策略：真实实现应调用检测模型执行推理。
        if len(image.bytes_data) < 512:
            return DetectionResult(
                success=True,
                boxes=[],
                latency_ms=int((time.time() - start) * 1000),
                reason="no_target_detected",
            )

        box = DetectionBox(
            label="bird",
            confidence=max(models.contract.detection.score_threshold, 0.62),
            x1=0.1,
            y1=0.15,
            x2=0.88,
            y2=0.9,
        )
        return DetectionResult(
            success=True,
            boxes=[box],
            latency_ms=int((time.time() - start) * 1000),
        )

    def classify(
        self,
        image: ImagePayload,
        detection: DetectionResult,
        models: LoadedModelBundle,
    ) -> ClassificationResult:
        _ = image
        start = time.time()

        if not detection.success or not detection.boxes:
            return ClassificationResult(
                success=False,
                latency_ms=int((time.time() - start) * 1000),
                reason="classification_skipped_no_detection",
            )

        labels = models.contract.classification.labels or ["unknown_bird"]
        top_label = labels[0]
        top_conf = 0.71
        topk = [
            ClassificationHit(label=top_label, confidence=top_conf),
        ]
        return ClassificationResult(
            success=True,
            top1_label=top_label,
            top1_confidence=top_conf,
            topk=topk,
            latency_ms=int((time.time() - start) * 1000),
        )

    def _crop_for_classification(
        self,
        image: ImagePayload,
        box: DetectionBox,
    ) -> tuple[ImagePayload, dict[str, float]]:
        with Image.open(io.BytesIO(image.bytes_data)) as raw:
            raw = raw.convert("RGB")
            width, height = raw.size

            left = int(max(0, min(width - 1, box.x1 * width)))
            top = int(max(0, min(height - 1, box.y1 * height)))
            right = int(max(left + 1, min(width, box.x2 * width)))
            bottom = int(max(top + 1, min(height, box.y2 * height)))

            cropped = raw.crop((left, top, right, bottom))
            output = io.BytesIO()
            save_format = "JPEG" if image.format.lower() in {"jpg", "jpeg"} else "PNG"
            cropped.save(output, format=save_format)

            cropped_payload = ImagePayload(
                image_id=f"{image.image_id}_crop",
                bytes_data=output.getvalue(),
                format=image.format,
                width=cropped.width,
                height=cropped.height,
                checksum_sha256=image.checksum_sha256,
            )
            crop_box = {
                "x1": box.x1,
                "y1": box.y1,
                "x2": box.x2,
                "y2": box.y2,
            }
            return cropped_payload, crop_box

    def infer_two_stage(
        self,
        image: ImagePayload,
        models: LoadedModelBundle,
    ) -> TwoStageInferenceResult:
        detection = self.detect(image=image, models=models)
        if not detection.success:
            return TwoStageInferenceResult(
                success=False,
                stage="detector_failed",
                detection=detection,
                classification=None,
                crop_applied=False,
                detector_model_version=models.contract.detection.model_version,
                classifier_model_version=models.contract.classification.model_version,
                reason=detection.reason or "detector_failed",
            )

        if not detection.boxes:
            return TwoStageInferenceResult(
                success=True,
                stage="detected_only",
                detection=detection,
                classification=None,
                crop_applied=False,
                detector_model_version=models.contract.detection.model_version,
                classifier_model_version=models.contract.classification.model_version,
                reason=detection.reason or "no_target_detected",
            )

        best_box = max(detection.boxes, key=lambda item: item.confidence)
        try:
            cropped_image, crop_box = self._crop_for_classification(
                image=image,
                box=best_box,
            )
        except Exception as exc:
            return TwoStageInferenceResult(
                success=False,
                stage="classifier_failed",
                detection=detection,
                classification=None,
                crop_applied=False,
                detector_model_version=models.contract.detection.model_version,
                classifier_model_version=models.contract.classification.model_version,
                reason=f"crop_failed:{exc}",
            )

        classification = self.classify(
            image=cropped_image,
            detection=detection,
            models=models,
        )
        if not classification.success:
            return TwoStageInferenceResult(
                success=False,
                stage="classifier_failed",
                detection=detection,
                classification=classification,
                crop_applied=True,
                crop_box=crop_box,
                detector_model_version=models.contract.detection.model_version,
                classifier_model_version=models.contract.classification.model_version,
                reason=classification.reason or "classifier_failed",
            )

        return TwoStageInferenceResult(
            success=True,
            stage="classified",
            detection=detection,
            classification=classification,
            crop_applied=True,
            crop_box=crop_box,
            detector_model_version=models.contract.detection.model_version,
            classifier_model_version=models.contract.classification.model_version,
        )
