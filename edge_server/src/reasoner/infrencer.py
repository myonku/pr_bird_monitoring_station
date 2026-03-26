from __future__ import annotations

import time

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
                detector_model_version=models.contract.detection.model_version,
                classifier_model_version=models.contract.classification.model_version,
                reason=detection.reason or "no_target_detected",
            )

        classification = self.classify(image=image, detection=detection, models=models)
        if not classification.success:
            return TwoStageInferenceResult(
                success=False,
                stage="classifier_failed",
                detection=detection,
                classification=classification,
                detector_model_version=models.contract.detection.model_version,
                classifier_model_version=models.contract.classification.model_version,
                reason=classification.reason or "classifier_failed",
            )

        return TwoStageInferenceResult(
            success=True,
            stage="classified",
            detection=detection,
            classification=classification,
            detector_model_version=models.contract.detection.model_version,
            classifier_model_version=models.contract.classification.model_version,
        )
