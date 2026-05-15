from __future__ import annotations

import io
import sys
import uuid
from contextlib import redirect_stdout
from pathlib import Path
from unittest import TestCase, main
from unittest.mock import patch


EDGE_SERVER_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(EDGE_SERVER_ROOT))

from src.models.sys.config import RuntimeLogConfig
from src.models.workflow.runtime import RuntimeStatus
from src.models.workflow.workflow import (
    CaptureContext,
    ClassificationHit,
    ClassificationResult,
    DetectionBox,
    DetectionResult,
    EdgeEvent,
    EdgeModelContract,
    ImagePayload,
    ModelArtifactContract,
    TwoStageInferenceResult,
)
from src.orchestration.decision_engine import DecisionEngine
from src.orchestration.pipeline import EdgePipeline
from src.utils.runtime_logger import RuntimeEventLogger


class _StaticCaptureModule:
    def __init__(self, context: CaptureContext, image: ImagePayload) -> None:
        self._context = context
        self._image = image

    def wait_and_capture(self, timeout_sec: float | None = None):
        return self._context, self._image


class _TimeoutCaptureModule:
    def wait_and_capture(self, timeout_sec: float | None = None):
        raise TimeoutError("capture_wait_timeout")


class _StaticInferenceModule:
    def __init__(self, contract: EdgeModelContract, result: TwoStageInferenceResult) -> None:
        self._contract = contract
        self._result = result

    def current_contract(self) -> EdgeModelContract:
        return self._contract

    def infer_two_stage(self, image: ImagePayload) -> TwoStageInferenceResult:
        return self._result


class _RecordingUploadCoordinator:
    def __init__(self, should_succeed: bool = True) -> None:
        self.should_succeed = should_succeed
        self.uploaded_event_ids: list[str] = []

    def upload_event(self, event: EdgeEvent) -> bool:
        self.uploaded_event_ids.append(event.event_id)
        return self.should_succeed


class _RecordingSpoolStorage:
    def __init__(self) -> None:
        self.records: list[tuple[str, str]] = []
        self._next_id = 1

    def put(self, event: EdgeEvent) -> str:
        record_id = f"record-{self._next_id}"
        self._next_id += 1
        self.records.append((record_id, event.event_id))
        return record_id


def _build_contract() -> EdgeModelContract:
    detection = ModelArtifactContract(
        artifact_id="detector-artifact",
        candidate_id="detector-candidate",
        task="detection",
        tier="standard",
        framework="mock",
        model_name="detector-model",
        format="custom",
        model_version="detector-v1",
        artifact_path="/models/detector",
        labels=["bird"],
        topk=1,
    )
    classification = ModelArtifactContract(
        artifact_id="classifier-artifact",
        candidate_id="classifier-candidate",
        task="classification",
        tier="standard",
        framework="mock",
        model_name="classifier-model",
        format="custom",
        model_version="classifier-v1",
        artifact_path="/models/classifier",
        labels=["heron", "duck"],
        topk=5,
    )
    return EdgeModelContract(
        contract_version="contract-v1",
        package_version="package-v1",
        exported_at_ms=1,
        exported_by="tests",
        detection=detection,
        classification=classification,
    )


def _build_inference_result(
    *,
    success: bool,
    stage: str,
    classification_confidence: float | None,
    reason: str | None,
) -> TwoStageInferenceResult:
    detection = DetectionResult(
        success=True,
        boxes=[
            DetectionBox(
                label="bird",
                confidence=0.91,
                x1=0.1,
                y1=0.1,
                x2=0.5,
                y2=0.5,
            )
        ],
        latency_ms=12,
        reason=None,
        model_signature="detector-sig",
    )
    classification = None
    if classification_confidence is not None:
        classification = ClassificationResult(
            success=True,
            top1_label="heron",
            top1_confidence=classification_confidence,
            topk=[ClassificationHit(label="heron", confidence=classification_confidence)],
            latency_ms=8,
            reason=None,
            model_signature="classifier-sig",
        )

    return TwoStageInferenceResult(
        success=success,
        stage=stage,
        detection=detection,
        classification=classification,
        crop_applied=classification is not None,
        crop_box=(
            {"x1": 0.1, "y1": 0.1, "x2": 0.5, "y2": 0.5}
            if classification is not None
            else None
        ),
        detector_model_version="detector-v1",
        classifier_model_version="classifier-v1",
        detector_model_signature="detector-sig",
        classifier_model_signature="classifier-sig",
        reason=reason,
    )


def _build_pipeline(
    *,
    runtime_status: RuntimeStatus,
    inference_result: TwoStageInferenceResult | None,
    confidence_threshold: float,
    upload_ok: bool,
) -> tuple[EdgePipeline, _RecordingUploadCoordinator, _RecordingSpoolStorage]:
    context = CaptureContext(
        device_id="edge-test",
        device_name="edge-device",
        location_name="wetland",
        trigger_type="motion",
        sensor_snapshot={"capture_mode": "mock"},
    )
    image = ImagePayload(
        image_id="image-1",
        bytes_data=b"image-bytes",
        format="jpg",
        width=1280,
        height=720,
        checksum_sha256="checksum",
    )
    contract = _build_contract()
    logger = RuntimeEventLogger(
        RuntimeLogConfig(
            enabled=True,
            include_timestamp=False,
            stages=["capture", "inference", "delivery"],
        )
    )
    upload = _RecordingUploadCoordinator(should_succeed=upload_ok)
    spool = _RecordingSpoolStorage()
    pipeline = EdgePipeline(
        capture=_StaticCaptureModule(context, image),
        infer=_StaticInferenceModule(
            contract,
            inference_result
            or _build_inference_result(
                success=False,
                stage="detector_failed",
                classification_confidence=None,
                reason="detector_failed",
            ),
        ),
        upload_coordinator=upload,
        spool=spool,
        decision_engine=DecisionEngine(
            enable_local_inference=True,
            confidence_threshold=confidence_threshold,
        ),
        runtime_status_provider=lambda: runtime_status,
        event_logger=logger,
    )
    return pipeline, upload, spool


class EdgePipelineLoggingTests(TestCase):
    def test_run_once_emits_compact_uploaded_summary(self) -> None:
        runtime_status = RuntimeStatus(
            network_ready=True,
            high_load=False,
            cpu_percent=0.12,
            memory_percent=0.18,
            network_reason=None,
            load_reason=None,
        )
        inference_result = _build_inference_result(
            success=True,
            stage="classified",
            classification_confidence=0.87,
            reason=None,
        )
        pipeline, upload, spool = _build_pipeline(
            runtime_status=runtime_status,
            inference_result=inference_result,
            confidence_threshold=0.6,
            upload_ok=True,
        )

        buffer = io.StringIO()
        with redirect_stdout(buffer), patch(
            "src.models.workflow.workflow.uuid.uuid4",
            side_effect=[
                uuid.UUID("11111111-1111-1111-1111-111111111111"),
                uuid.UUID("22222222-2222-2222-2222-222222222222"),
            ],
        ):
            processed = pipeline.run_once()

        self.assertTrue(processed)
        self.assertEqual(upload.uploaded_event_ids, ["11111111-1111-1111-1111-111111111111"])
        self.assertEqual(spool.records, [])
        self.assertEqual(
            buffer.getvalue().splitlines(),
            [
                "=" * 70,
                "[edge] [capture] trigger_started event_id=11111111-1111-1111-1111-111111111111 trigger=motion",
                "[edge] [inference] inference_summary event_id=11111111-1111-1111-1111-111111111111 executed=True success=True stage=classified detection_label=bird detection_confidence=0.910 classification_label=heron classification_confidence=0.870 server_assist=False reason=local_inference_confident",
                "[edge] [delivery] trigger_finished event_id=11111111-1111-1111-1111-111111111111 final_result=uploaded stored_locally=False server_assist=False reason=local_inference_confident",
            ],
        )

    def test_run_once_emits_local_spool_summary_when_assist_is_required(self) -> None:
        runtime_status = RuntimeStatus(
            network_ready=False,
            high_load=False,
            cpu_percent=0.12,
            memory_percent=0.18,
            network_reason="upload_endpoint_unavailable",
            load_reason=None,
        )
        inference_result = _build_inference_result(
            success=True,
            stage="classified",
            classification_confidence=0.52,
            reason=None,
        )
        pipeline, upload, spool = _build_pipeline(
            runtime_status=runtime_status,
            inference_result=inference_result,
            confidence_threshold=0.9,
            upload_ok=True,
        )

        buffer = io.StringIO()
        with redirect_stdout(buffer), patch(
            "src.models.workflow.workflow.uuid.uuid4",
            side_effect=[
                uuid.UUID("33333333-3333-3333-3333-333333333333"),
                uuid.UUID("44444444-4444-4444-4444-444444444444"),
            ],
        ):
            processed = pipeline.run_once()

        self.assertTrue(processed)
        self.assertEqual(upload.uploaded_event_ids, [])
        self.assertEqual(spool.records, [("record-1", "33333333-3333-3333-3333-333333333333")])
        self.assertEqual(
            buffer.getvalue().splitlines(),
            [
                "=" * 70,
                "[edge] [capture] trigger_started event_id=33333333-3333-3333-3333-333333333333 trigger=motion",
                "[edge] [inference] inference_summary event_id=33333333-3333-3333-3333-333333333333 executed=True success=True stage=classified detection_label=bird detection_confidence=0.910 classification_label=heron classification_confidence=0.520 server_assist=True reason=low_confidence",
                "[edge] [delivery] trigger_finished event_id=33333333-3333-3333-3333-333333333333 final_result=spooled_by_policy stored_locally=True server_assist=True reason=low_confidence",
            ],
        )

    def test_run_once_is_silent_when_capture_times_out(self) -> None:
        runtime_status = RuntimeStatus(
            network_ready=True,
            high_load=False,
            cpu_percent=0.12,
            memory_percent=0.18,
            network_reason=None,
            load_reason=None,
        )
        pipeline, upload, spool = _build_pipeline(
            runtime_status=runtime_status,
            inference_result=None,
            confidence_threshold=0.6,
            upload_ok=True,
        )
        pipeline.capture = _TimeoutCaptureModule()

        buffer = io.StringIO()
        with redirect_stdout(buffer):
            processed = pipeline.run_once()

        self.assertFalse(processed)
        self.assertEqual(upload.uploaded_event_ids, [])
        self.assertEqual(spool.records, [])
        self.assertEqual(buffer.getvalue(), "")


if __name__ == "__main__":
    main()