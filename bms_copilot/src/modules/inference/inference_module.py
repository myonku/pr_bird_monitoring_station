from __future__ import annotations

import io
import time

from PIL import Image

from src.iface.inference.inference import IInferenceModule
from src.models.inference.config import InferenceConfig
from src.models.inference.workflow import (
    ClassificationResult,
    DetectionBox,
    DetectionResult,
    InferenceImagePayload,
    LoadedInferenceBundle,
    TwoStageInferenceResult,
)
from src.modules.inference.classification_runtime import ClassificationRuntime
from src.modules.inference.detection_runtime import DetectionRuntime
from src.modules.inference.model_loader import LocalModelBundleLoader
from src.modules.inference.runtime_common import build_model_signature, load_rgb

class TwoStageInferenceModule(IInferenceModule):
    """标准级两阶段推理：检测 -> 分类；检测失败或无目标时提前退出。"""

    def __init__(
        self,
        inference_bundle: LoadedInferenceBundle,
        detection_runtime: DetectionRuntime | None = None,
        classification_runtime: ClassificationRuntime | None = None,
    ) -> None:
        self._inference_bundle = inference_bundle
        self._detection_runtime = detection_runtime or DetectionRuntime()
        self._classification_runtime = classification_runtime or ClassificationRuntime()

    @staticmethod
    def _elapsed_ms(start_time: float) -> int:
        return int((time.time() - start_time) * 1000)

    @staticmethod
    def _model_signature_for_detection(bundle: LoadedInferenceBundle) -> str:
        handle = (
            bundle.detection_handle if isinstance(bundle.detection_handle, dict) else {}
        )
        return build_model_signature(handle, bundle.contract.detection)

    @staticmethod
    def _model_signature_for_classification(bundle: LoadedInferenceBundle) -> str:
        handle = (
            bundle.classification_handle
            if isinstance(bundle.classification_handle, dict)
            else {}
        )
        return build_model_signature(handle, bundle.contract.classification)

    def detect(
        self,
        image: InferenceImagePayload,
    ) -> DetectionResult:
        models = self._inference_bundle
        start = time.time()
        model_signature = self._model_signature_for_detection(models)

        if not image.bytes_data:
            return DetectionResult(
                success=False,
                boxes=[],
                latency_ms=self._elapsed_ms(start),
                reason="empty_image",
                model_signature=model_signature,
            )

        try:
            rgb = load_rgb(image)
            handle = (
                models.detection_handle
                if isinstance(models.detection_handle, dict)
                else {}
            )
            labels = list(models.contract.detection.labels)
            score_threshold = float(models.contract.detection.score_threshold)
            boxes = self._detection_runtime.run(
                image=rgb,
                handle=handle,
                labels=labels,
                score_threshold=score_threshold,
            )
        except Exception as exc:
            return DetectionResult(
                success=False,
                boxes=[],
                latency_ms=self._elapsed_ms(start),
                reason=f"detector_runtime_error:{exc}",
                model_signature=model_signature,
            )

        reason = "no_target_detected" if not boxes else None
        return DetectionResult(
            success=True,
            boxes=boxes,
            latency_ms=self._elapsed_ms(start),
            reason=reason,
            model_signature=model_signature,
        )

    def classify(
        self,
        image: InferenceImagePayload,
        detection: DetectionResult,
    ) -> ClassificationResult:
        models = self._inference_bundle
        start = time.time()
        model_signature = self._model_signature_for_classification(models)

        if not detection.success or not detection.boxes:
            return ClassificationResult(
                success=False,
                latency_ms=self._elapsed_ms(start),
                reason="classification_skipped_no_detection",
                model_signature=model_signature,
            )

        try:
            rgb = load_rgb(image)
            handle = (
                models.classification_handle
                if isinstance(models.classification_handle, dict)
                else {}
            )
            labels = list(models.contract.classification.labels)
            topk_limit = max(1, int(models.contract.classification.topk))
            topk = self._classification_runtime.run(
                image=rgb,
                handle=handle,
                labels=labels,
                topk=topk_limit,
            )
        except Exception as exc:
            return ClassificationResult(
                success=False,
                latency_ms=self._elapsed_ms(start),
                reason=f"classifier_runtime_error:{exc}",
                model_signature=model_signature,
            )

        if not topk:
            return ClassificationResult(
                success=False,
                latency_ms=self._elapsed_ms(start),
                reason="classifier_empty_output",
                model_signature=model_signature,
            )

        return ClassificationResult(
            success=True,
            top1_label=topk[0].label,
            top1_confidence=topk[0].confidence,
            topk=topk,
            latency_ms=self._elapsed_ms(start),
            model_signature=model_signature,
        )

    def _crop_for_classification(
        self,
        image: InferenceImagePayload,
        box: DetectionBox,
    ) -> tuple[InferenceImagePayload, dict[str, float]]:
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

            cropped_payload = InferenceImagePayload(
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
        image: InferenceImagePayload,
    ) -> TwoStageInferenceResult:
        models = self._inference_bundle
        detector_signature = self._model_signature_for_detection(models)
        classifier_signature = self._model_signature_for_classification(models)

        detection = self.detect(image=image)
        if not detection.success:
            return TwoStageInferenceResult(
                success=False,
                stage="detector_failed",
                detection=detection,
                classification=None,
                crop_applied=False,
                detector_model_version=models.contract.detection.model_version,
                classifier_model_version=models.contract.classification.model_version,
                detector_model_signature=detection.model_signature
                or detector_signature,
                classifier_model_signature=classifier_signature,
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
                detector_model_signature=detection.model_signature
                or detector_signature,
                classifier_model_signature=classifier_signature,
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
                detector_model_signature=detection.model_signature
                or detector_signature,
                classifier_model_signature=classifier_signature,
                reason=f"crop_failed:{exc}",
            )

        classification = self.classify(image=cropped_image, detection=detection)
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
                detector_model_signature=detection.model_signature
                or detector_signature,
                classifier_model_signature=classification.model_signature
                or classifier_signature,
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
            detector_model_signature=detection.model_signature or detector_signature,
            classifier_model_signature=classification.model_signature
            or classifier_signature,
        )


def build_standard_inference_module(config: InferenceConfig) -> TwoStageInferenceModule:
    loader = LocalModelBundleLoader()
    bundle = loader.load(config)
    return TwoStageInferenceModule(inference_bundle=bundle)
