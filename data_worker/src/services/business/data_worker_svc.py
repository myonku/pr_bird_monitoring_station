from __future__ import annotations

import asyncio
import base64
import binascii
import json
from dataclasses import dataclass
from typing import Any

from src.iface.business.data_worker_svc import IDataWorkerService
from src.iface.business.envelope_svc import IEnvelopeManager
from src.iface.business.monitoring_record_svc import IMonitoringRecordManager
from src.iface.business.species_profile_svc import ISpeciesProfileManager
from src.iface.inference.inference import IInferenceModule
from src.models.business.data import EdgeEventEnvelope, MonitoringRecord, ProcessingSource
from src.models.business.event_req_dto import EdgeEventUploadRequest
from src.models.common.entities import SpeciesProfile
from src.models.inference.workflow import InferenceImagePayload, TwoStageInferenceResult


@dataclass(slots=True, kw_only=True)
class StageAResult:
    enter_stage_b: bool
    processing_source: ProcessingSource
    inference_result: TwoStageInferenceResult | None = None
    reason: str = ""


@dataclass(slots=True, kw_only=True)
class StageBInput:
    request: EdgeEventUploadRequest
    envelope: EdgeEventEnvelope
    processing_source: ProcessingSource
    image_b64: str = ""
    inference_result: TwoStageInferenceResult | None = None
    stage_a_reason: str = ""


class DataWorkerService(IDataWorkerService):
    """data_worker 业务流水线实现（阶段 A/B）。"""

    def __init__(
        self,
        *,
        envelope_manager: IEnvelopeManager,
        monitoring_record_manager: IMonitoringRecordManager,
        species_profile_manager: ISpeciesProfileManager,
        inference_module: IInferenceModule | None = None,
        min_classification_confidence: float = 0.5,
    ) -> None:
        if envelope_manager is None:
            raise ValueError("envelope manager is required")
        if monitoring_record_manager is None:
            raise ValueError("monitoring record manager is required")
        if species_profile_manager is None:
            raise ValueError("species profile manager is required")

        self._envelope_manager = envelope_manager
        self._monitoring_record_manager = monitoring_record_manager
        self._species_profile_manager = species_profile_manager
        self._inference_module = inference_module
        self._min_classification_confidence = max(
            0.0, float(min_classification_confidence)
        )

    async def handle_edge_upload(
        self,
        request: EdgeEventUploadRequest,
    ) -> MonitoringRecord | None:
        if request is None:
            raise ValueError("edge event request is required")

        envelope = request.to_document()
        await self._upsert_envelope(envelope)

        stage_a = await self._run_stage_a(request)
        if not stage_a.enter_stage_b:
            return None

        stage_b = self._build_stage_b_input(request, stage_a, envelope)

        species_profile = await self._resolve_species_profile(stage_b)
        monitoring_record = self._build_monitoring_record(stage_b, species_profile)
        return await self._monitoring_record_manager.create(monitoring_record)

    async def _run_stage_a(self, request: EdgeEventUploadRequest) -> StageAResult:
        if not request.requires_server_assist:
            return StageAResult(
                enter_stage_b=True,
                processing_source="edge",
                inference_result=request.local_inference,
                reason="server_assist_not_required",
            )

        if self._inference_module is None:
            return StageAResult(
                enter_stage_b=False,
                processing_source="data_worker",
                reason="server_inference_unavailable",
            )

        inference_image = await self._build_inference_image_payload(request)
        if inference_image is None:
            return StageAResult(
                enter_stage_b=False,
                processing_source="data_worker",
                reason="invalid_edge_image_payload",
            )

        inference_result = await self._infer_two_stage_async(inference_image)
        drop_reason = self._resolve_stage_a_drop_reason(inference_result)
        if drop_reason:
            return StageAResult(
                enter_stage_b=False,
                processing_source="data_worker",
                inference_result=inference_result,
                reason=drop_reason,
            )

        return StageAResult(
            enter_stage_b=True,
            processing_source="data_worker",
            inference_result=inference_result,
            reason="server_inference_accepted",
        )

    async def _infer_two_stage_async(
        self,
        image: InferenceImagePayload,
    ) -> TwoStageInferenceResult:
        if self._inference_module is None:
            raise RuntimeError("inference module is required")

        return await asyncio.to_thread(
            self._inference_module.infer_two_stage,
            image,
        )

    async def _build_inference_image_payload(
        self,
        request: EdgeEventUploadRequest,
    ) -> InferenceImagePayload | None:
        raw_image_b64 = (request.image_b64 or "").strip()
        if not raw_image_b64:
            return None

        try:
            image_bytes = await asyncio.to_thread(
                lambda: base64.b64decode(raw_image_b64, validate=True)
            )
        except (binascii.Error, ValueError):
            return None

        if not image_bytes:
            return None

        return InferenceImagePayload(
            image_id=request.image.image_id,
            bytes_data=image_bytes,
            format=request.image.format,
            width=request.image.width,
            height=request.image.height,
            checksum_sha256=request.image.checksum_sha256,
        )

    def _resolve_stage_a_drop_reason(
        self,
        inference_result: TwoStageInferenceResult | None,
    ) -> str:
        if inference_result is None:
            return "server_inference_empty"

        if not inference_result.success:
            return inference_result.reason or "server_inference_failed"

        if inference_result.stage in {"detector_failed", "classifier_failed"}:
            return inference_result.reason or inference_result.stage

        if inference_result.stage == "detected_only":
            return "no_target_detected"

        classification = inference_result.classification
        if classification is None or not classification.success:
            return "classification_missing"

        top1_label = (classification.top1_label or "").strip()
        if not top1_label:
            return "classification_label_missing"

        confidence = float(classification.top1_confidence or 0.0)
        if confidence < self._min_classification_confidence:
            return "classification_confidence_too_low"

        return ""

    def _build_stage_b_input(
        self,
        request: EdgeEventUploadRequest,
        stage_a: StageAResult,
        envelope: EdgeEventEnvelope,
    ) -> StageBInput:
        return StageBInput(
            request=request,
            envelope=envelope,
            processing_source=stage_a.processing_source,
            image_b64=request.image_b64,
            inference_result=stage_a.inference_result,
            stage_a_reason=stage_a.reason,
        )

    async def _upsert_envelope(self, envelope: EdgeEventEnvelope) -> None:
        existing = await self._envelope_manager.get_by_id(envelope.event_id)
        if existing is None:
            await self._envelope_manager.create(envelope)
            return
        await self._envelope_manager.update(envelope)

    async def _resolve_species_profile(
        self,
        stage_b: StageBInput,
    ) -> SpeciesProfile | None:
        species_hint = self._resolve_species_hint(stage_b)
        if not species_hint:
            return None

        by_scientific = await self._species_profile_manager.get_by_scientific_name(
            species_hint
        )
        if by_scientific is not None:
            return by_scientific

        return await self._species_profile_manager.get_by_display_name(species_hint)

    def _resolve_species_hint(self, stage_b: StageBInput) -> str:
        inference = stage_b.inference_result
        if (
            inference is not None
            and inference.classification is not None
            and inference.classification.success
        ):
            hint = (inference.classification.top1_label or "").strip()
            if hint:
                return hint

        metadata = dict(stage_b.request.metadata or {})
        for key in ("species_name", "scientific_name", "top1_label"):
            hint = str(metadata.get(key, "") or "").strip()
            if hint:
                return hint

        return ""

    def _build_monitoring_record(
        self,
        stage_b: StageBInput,
        species_profile: SpeciesProfile | None,
    ) -> MonitoringRecord:
        species_hint = self._resolve_species_hint(stage_b)
        confidence = self._resolve_species_confidence(stage_b.inference_result)

        species_name = (
            species_profile.display_name.strip()
            if species_profile is not None and species_profile.display_name.strip()
            else species_hint or "unknown"
        )
        scientific_name = (
            species_profile.scientific_name.strip()
            if species_profile is not None and species_profile.scientific_name.strip()
            else species_hint
        )

        env = stage_b.request.context.environment_snapshot

        return MonitoringRecord(
            device_entity_id=stage_b.envelope.device_entity_id,
            device_name=stage_b.request.context.device_name,
            source_event_id=stage_b.request.event_id,
            species_entity_id=(
                species_profile.species_entity_id if species_profile is not None else None
            ),
            captured_at_ms=max(int(stage_b.request.context.captured_at_ms), 0),
            species_name=species_name,
            scientific_name=scientific_name,
            confidence=confidence,
            temperature_c=env.temperature_c if env is not None else None,
            humidity_pct=env.humidity_pct if env is not None else None,
            image_b64=stage_b.image_b64,
            media_refs=self._build_media_refs(stage_b.request),
            processing_source=stage_b.processing_source,
            model_version=self._resolve_model_version(stage_b.inference_result),
            summary_text=self._build_summary_text(stage_b.inference_result),
            species_intro=(species_profile.intro if species_profile is not None else ""),
            record_status="stored",
            metadata=self._build_record_metadata(stage_b, species_profile),
        )

    @staticmethod
    def _resolve_species_confidence(
        inference_result: TwoStageInferenceResult | None,
    ) -> float:
        if (
            inference_result is None
            or inference_result.classification is None
            or not inference_result.classification.success
        ):
            return 0.0
        return float(inference_result.classification.top1_confidence or 0.0)

    @staticmethod
    def _resolve_model_version(
        inference_result: TwoStageInferenceResult | None,
    ) -> str:
        if inference_result is None:
            return ""
        if (inference_result.classifier_model_version or "").strip():
            return inference_result.classifier_model_version or ""
        if (inference_result.detector_model_version or "").strip():
            return inference_result.detector_model_version or ""
        return ""

    @staticmethod
    def _build_summary_text(inference_result: TwoStageInferenceResult | None) -> str:
        if inference_result is None:
            return "edge_event_received_without_inference"

        if (
            inference_result.classification is not None
            and inference_result.classification.success
            and (inference_result.classification.top1_label or "").strip()
        ):
            return f"classified:{inference_result.classification.top1_label}"

        if (inference_result.reason or "").strip():
            return inference_result.reason or ""

        return f"inference_stage:{inference_result.stage}"

    @staticmethod
    def _build_media_refs(request: EdgeEventUploadRequest) -> list[str]:
        refs = [f"edge_image:{request.image.image_id}"]
        checksum = (request.image.checksum_sha256 or "").strip()
        if checksum:
            refs.append(f"checksum_sha256:{checksum}")
        return refs

    def _build_record_metadata(
        self,
        stage_b: StageBInput,
        species_profile: SpeciesProfile | None,
    ) -> dict[str, str]:
        metadata: dict[str, str] = {
            "trace_id": str(stage_b.request.trace_id),
            "request_event_id": str(stage_b.request.event_id),
            "stage_a_reason": stage_b.stage_a_reason,
            "processing_source": stage_b.processing_source,
            "requires_server_assist": str(stage_b.request.requires_server_assist),
        }

        if stage_b.inference_result is not None:
            metadata["inference_stage"] = stage_b.inference_result.stage
            metadata["inference_reason"] = stage_b.inference_result.reason or ""

        if species_profile is not None:
            metadata["species_profile_entity_id"] = str(
                species_profile.species_entity_id
            )

        for key, value in dict(stage_b.request.metadata or {}).items():
            metadata[str(key)] = self._stringify_metadata_value(value)

        return metadata

    @staticmethod
    def _stringify_metadata_value(value: Any) -> str:
        if value is None:
            return ""
        if isinstance(value, str):
            return value
        if isinstance(value, (bool, int, float)):
            return str(value)
        try:
            return json.dumps(value, ensure_ascii=True)
        except TypeError:
            return str(value)
