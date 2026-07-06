# pyright: reportAttributeAccessIssue=false
# type: ignore
from __future__ import annotations

import json
from types import SimpleNamespace
from unittest import IsolatedAsyncioTestCase
from unittest.mock import patch
from uuid import UUID, uuid4

from src.gen.business.v1 import business_forward_pb2
from src.iface.business.data_worker_svc import EdgeEventProcessingResult
from src.iface.communication.routing_contract import RouteProfile
from src.models.business.event_req_dto import (
    CaptureContextRequest,
    EdgeEventUploadRequest,
    ImagePayloadRequest,
    TemperatureHumiditySnapshotRequest,
)
from src.models.business.entities import SpeciesProfile
from src.models.inference.workflow import (
    ClassificationResult,
    DetectionResult,
    TwoStageInferenceResult,
)
from src.services.business.data_worker_svc import DataWorkerService
from src.services.communication.rpc_service.business_forward_servicer import (
    BusinessForwardServicer,
)


class FakeEnvelopeManager:
    def __init__(self) -> None:
        self.envelopes: dict[UUID, object] = {}
        self.create_calls: list[object] = []

    async def get_by_id(self, event_id: UUID):
        return self.envelopes.get(event_id)

    async def list_all(self):
        return list(self.envelopes.values())

    async def create(self, envelope):
        self.create_calls.append(envelope)
        self.envelopes[getattr(envelope, "event_id")] = envelope
        return envelope

    async def update(self, envelope):
        self.envelopes[getattr(envelope, "event_id")] = envelope
        return envelope

    async def delete(self, event_id: UUID):
        self.envelopes.pop(event_id, None)
        return True

    async def count_today_upload_records(self):
        return len(self.envelopes)

    async def get_today_top_upload_site(self):
        return None

    async def get_latest_upload_summary(self):
        return None


class FakeMonitoringRecordManager:
    def __init__(self) -> None:
        self.create_calls: list[object] = []

    async def get_by_id(self, record_id: UUID):
        return None

    async def list_recent_week(self, device_entity_id: UUID | None = None):
        return []

    async def list_by_day_range(self, start_day, end_day, device_entity_id: UUID | None = None):
        return []

    async def list_all(self):
        return []

    async def create(self, record):
        self.create_calls.append(record)
        return record

    async def update(self, record):
        return record

    async def delete(self, record_id: UUID):
        return True

    async def count_today_monitoring_records(self):
        return len(self.create_calls)

    async def list_latest_three(self):
        return list(self.create_calls[-3:])

    async def list_recent_week_daily_counts(self):
        return []


class FakeSpeciesProfileManager:
    def __init__(self) -> None:
        self.label_lookup: dict[str, SpeciesProfile] = {}

    async def get_by_id(self, species_entity_id: UUID):
        return None

    async def get_by_scientific_name(self, scientific_name: str):
        return None

    async def get_by_label_name(self, label_name: str):
        return self.label_lookup.get(label_name)

    async def get_by_display_name(self, display_name: str):
        return None

    async def list_all(self):
        return []

    async def create(self, profile):
        return uuid4()

    async def update(self, profile):
        return False

    async def delete(self, species_entity_id: UUID):
        return False


class FakeTrafficStation:
    def __init__(self, *, accepted: bool = True, reason: str = "accepted") -> None:
        self.accepted = accepted
        self.reason = reason
        self.calls: list[object] = []

    async def handle_inbound(self, req):
        self.calls.append(req)
        profile = RouteProfile(
            target_service_type="internal_service",
            target_service_name="data_worker",
            target_endpoint="127.0.0.1:50052",
            flow_category="business_forward",
            security_policy="required",
        )
        return SimpleNamespace(
            accepted=self.accepted,
            reason=self.reason,
            profile=profile,
            metadata={"flow_category": "business_forward"},
        )

    async def send_outbound(self, req):
        raise NotImplementedError


class FakeMonitoringRecord:
    def __init__(self, *, source_event_id: UUID, device_entity_id: UUID) -> None:
        self.id = uuid4()
        self.device_entity_id = device_entity_id
        self.device_name = "wetland-station"
        self.source_event_id = source_event_id
        self.species_name = "sparrow"
        self.scientific_name = "Passer domesticus"
        self.confidence = 0.93
        self.processing_source = "edge"

    @property
    def record_id(self) -> UUID:
        return self.id

    def model_dump(self, mode: str = "python") -> dict[str, object]:
        return {
            "id": str(self.id),
            "device_entity_id": str(self.device_entity_id),
            "device_name": self.device_name,
            "source_event_id": str(self.source_event_id),
            "species_name": self.species_name,
            "scientific_name": self.scientific_name,
            "confidence": self.confidence,
            "processing_source": self.processing_source,
        }


class FakeDataWorkerService:
    def __init__(self, result: EdgeEventProcessingResult) -> None:
        self.result = result
        self.requests: list[EdgeEventUploadRequest] = []

    async def handle_edge_upload(self, request: EdgeEventUploadRequest) -> EdgeEventProcessingResult:
        self.requests.append(request)
        return self.result


def build_edge_event_request() -> EdgeEventUploadRequest:
    return EdgeEventUploadRequest(
        event_id=uuid4(),
        trace_id=uuid4(),
        context=CaptureContextRequest(
            device_id=str(uuid4()),
            device_name="wetland-station",
            location_name="north-lake",
            trigger_type="manual",
            sensor_snapshot={"mode": "test"},
            environment_snapshot=TemperatureHumiditySnapshotRequest(
                temperature_c=21.5,
                humidity_pct=60,
                source="mock",
                sensor_snapshot={},
                captured_at_ms=1700000000000,
            ),
            captured_at_ms=1700000000000,
        ),
        image=ImagePayloadRequest(
            image_id="image-1",
            format="jpg",
            width=640,
            height=480,
            checksum_sha256="deadbeef",
        ),
        local_inference=None,
        requires_server_assist=False,
        metadata={"origin": "edge"},
        image_b64="",
    )


class DataWorkerBusinessForwardTests(IsolatedAsyncioTestCase):
    async def test_handle_edge_upload_returns_processing_result(self) -> None:
        envelope_manager = FakeEnvelopeManager()
        monitoring_record_manager = FakeMonitoringRecordManager()
        species_profile_manager = FakeSpeciesProfileManager()
        service = DataWorkerService(
            envelope_manager=envelope_manager,
            monitoring_record_manager=monitoring_record_manager,
            species_profile_manager=species_profile_manager,
            inference_module=None,
        )

        request = build_edge_event_request().model_copy(
            update={
                "local_inference": TwoStageInferenceResult(
                    success=True,
                    stage="classified",
                    detection=DetectionResult(success=True),
                    classification=ClassificationResult(
                        success=True,
                        top1_label="sparrow",
                        top1_confidence=0.93,
                    ),
                )
            }
        )
        fake_envelope = SimpleNamespace(
            event_id=request.event_id,
            device_entity_id=UUID(request.context.device_id),
            device_name=request.context.device_name,
            occurred_at_ms=request.context.captured_at_ms,
            received_at_ms=request.context.captured_at_ms,
            payload_version="edge_event_http_v1",
            payload_type="mixed",
            payload_body={"event_id": str(request.event_id)},
            payload_mongo_document_id="",
            binary_parts=[],
            transport_meta={"source": "edge_server"},
            metadata={"origin": "edge"},
        )
        fake_record = FakeMonitoringRecord(
            source_event_id=request.event_id,
            device_entity_id=UUID(request.context.device_id),
        )

        with patch.object(EdgeEventUploadRequest, "to_document", return_value=fake_envelope):
            with patch.object(service, "_build_monitoring_record", return_value=fake_record):
                result = await service.handle_edge_upload(request)

        self.assertTrue(result.stage_a_enter_stage_b)
        self.assertEqual(result.processing_source, "edge")
        self.assertEqual(result.stage_a_reason, "server_assist_not_required")
        self.assertIs(result.envelope, fake_envelope)
        self.assertIs(result.monitoring_record, fake_record)
        self.assertEqual(len(envelope_manager.create_calls), 1)
        self.assertEqual(len(monitoring_record_manager.create_calls), 1)

    async def test_handle_edge_upload_drops_low_confidence_records(self) -> None:
        envelope_manager = FakeEnvelopeManager()
        monitoring_record_manager = FakeMonitoringRecordManager()
        species_profile_manager = FakeSpeciesProfileManager()
        service = DataWorkerService(
            envelope_manager=envelope_manager,
            monitoring_record_manager=monitoring_record_manager,
            species_profile_manager=species_profile_manager,
            inference_module=None,
        )

        request = build_edge_event_request().model_copy(
            update={
                "local_inference": TwoStageInferenceResult(
                    success=True,
                    stage="classified",
                    detection=DetectionResult(success=True),
                    classification=ClassificationResult(
                        success=True,
                        top1_label="sparrow",
                        top1_confidence=0.80,
                    ),
                )
            }
        )
        fake_envelope = SimpleNamespace(
            event_id=request.event_id,
            device_entity_id=UUID(request.context.device_id),
            device_name=request.context.device_name,
            occurred_at_ms=request.context.captured_at_ms,
            received_at_ms=request.context.captured_at_ms,
            payload_version="edge_event_http_v1",
            payload_type="mixed",
            payload_body={"event_id": str(request.event_id)},
            payload_mongo_document_id="",
            binary_parts=[],
            transport_meta={"source": "edge_server"},
            metadata={"origin": "edge"},
        )

        with patch.object(EdgeEventUploadRequest, "to_document", return_value=fake_envelope):
            result = await service.handle_edge_upload(request)

        self.assertTrue(result.stage_a_enter_stage_b)
        self.assertEqual(result.stage_a_reason, "classification_confidence_too_low")
        self.assertIsNone(result.monitoring_record)
        self.assertEqual(len(envelope_manager.create_calls), 1)
        self.assertEqual(len(monitoring_record_manager.create_calls), 0)

    async def test_handle_edge_upload_resolves_species_profile_by_label_name(self) -> None:
        envelope_manager = FakeEnvelopeManager()
        monitoring_record_manager = FakeMonitoringRecordManager()
        species_profile_manager = FakeSpeciesProfileManager()
        label_name = "Pycnonotus sinensis"
        species_profile_manager.label_lookup[label_name] = SpeciesProfile(
            species_entity_id=uuid4(),
            scientific_name="Pycnonotus sinensis",
            label_name=label_name,
            display_name="白头鹎",
            intro="",
            habitat="",
            protection_level="",
            alias_names=[],
            metadata={},
        )
        service = DataWorkerService(
            envelope_manager=envelope_manager,
            monitoring_record_manager=monitoring_record_manager,
            species_profile_manager=species_profile_manager,
            inference_module=None,
        )

        request = build_edge_event_request().model_copy(
            update={
                "local_inference": TwoStageInferenceResult(
                    success=True,
                    stage="classified",
                    detection=DetectionResult(success=True),
                    classification=ClassificationResult(
                        success=True,
                        top1_label=label_name,
                        top1_confidence=0.92,
                    ),
                )
            }
        )
        fake_envelope = SimpleNamespace(
            event_id=request.event_id,
            device_entity_id=UUID(request.context.device_id),
            device_name=request.context.device_name,
            occurred_at_ms=request.context.captured_at_ms,
            received_at_ms=request.context.captured_at_ms,
            payload_version="edge_event_http_v1",
            payload_type="mixed",
            payload_body={"event_id": str(request.event_id)},
            payload_mongo_document_id="",
            binary_parts=[],
            transport_meta={"source": "edge_server"},
            metadata={"origin": "edge"},
        )

        with patch.object(EdgeEventUploadRequest, "to_document", return_value=fake_envelope):
            result = await service.handle_edge_upload(request)

        self.assertTrue(result.stage_a_enter_stage_b)
        self.assertEqual(len(monitoring_record_manager.create_calls), 1)
        created_record = monitoring_record_manager.create_calls[0]
        self.assertEqual(created_record.species_name, "白头鹎")
        self.assertEqual(created_record.scientific_name, "Pycnonotus sinensis")
        self.assertEqual(created_record.device_entity_id, UUID(request.context.device_id))
        self.assertIs(result.monitoring_record, created_record)

    async def test_forward_business_maps_payload_and_merges_gateway_context(self) -> None:
        request = build_edge_event_request()
        fake_envelope = SimpleNamespace(
            event_id=request.event_id,
            device_entity_id=UUID(request.context.device_id),
            device_name=request.context.device_name,
            occurred_at_ms=request.context.captured_at_ms,
            received_at_ms=request.context.captured_at_ms,
            payload_version="edge_event_http_v1",
            payload_type="mixed",
            payload_body={"event_id": str(request.event_id)},
            payload_mongo_document_id="",
            binary_parts=[],
            transport_meta={"source": "edge_server"},
            metadata={"origin": "edge"},
        )
        fake_record = FakeMonitoringRecord(
            source_event_id=request.event_id,
            device_entity_id=UUID(request.context.device_id),
        )
        processing_result = EdgeEventProcessingResult(
            request=request,
            envelope=fake_envelope,
            processing_source="edge",
            stage_a_enter_stage_b=True,
            stage_a_reason="server_assist_not_required",
            monitoring_record=fake_record,
        )
        data_worker_service = FakeDataWorkerService(processing_result)
        traffic_station = FakeTrafficStation()
        servicer = BusinessForwardServicer(
            traffic_station=traffic_station,
            data_worker_service=data_worker_service,
            expected_service_name="data_worker",
        )

        payload = {
            "event_id": str(request.event_id),
            "trace_id": str(request.trace_id),
            "context": {
                "device_id": request.context.device_id,
                "device_name": request.context.device_name,
                "location_name": request.context.location_name,
                "trigger_type": request.context.trigger_type,
                "sensor_snapshot": request.context.sensor_snapshot,
                "environment_snapshot": {
                    "temperature_c": 21.5,
                    "humidity_pct": 60,
                    "source": "mock",
                    "sensor_snapshot": {},
                    "captured_at_ms": 1700000000000,
                },
                "captured_at_ms": request.context.captured_at_ms,
            },
            "image": {
                "image_id": request.image.image_id,
                "format": request.image.format,
                "width": request.image.width,
                "height": request.image.height,
                "checksum_sha256": request.image.checksum_sha256,
            },
            "local_inference": None,
            "requires_server_assist": False,
            "metadata": {"payload_key": "payload_value"},
            "image_b64": "",
        }

        grpc_request = business_forward_pb2.BusinessForwardRequest(
            route_key="business.forward.generic",
            operation="edge.events.upload",
            flow_category="business_forward",
            source_service="gateway",
            target_service_type="internal_service",
            target_service_name="data_worker",
            target_endpoint="127.0.0.1:50052",
            request_id="req-123",
            trace_id="trace-456",
            headers={"x-client-id": "gateway-client"},
            auth_context=business_forward_pb2.BusinessAuthContext(
                principal_id="principal-1",
                session_id="session-1",
                token_id="token-1",
                token_family_id="family-1",
                token_type="access",
                scopes=["edge:upload"],
                auth_method="gateway_auth",
                client_id="gateway-client",
                gateway_id="gateway-1",
                source_ip="127.0.0.1",
                user_agent="test-agent",
                issued_at_ms=1700000000000,
                expires_at_ms=1700003600000,
            ),
            metadata={"route_hint": "edge-events"},
            payload=json.dumps(payload, ensure_ascii=False),
        )

        response = await servicer.ForwardBusiness(grpc_request, None)

        self.assertTrue(response.accepted)
        self.assertEqual(response.status, "stored")
        self.assertEqual(response.route_key, "business.forward.generic")
        self.assertEqual(response.operation, "edge.events.upload")
        self.assertEqual(response.target_service_name, "data_worker")
        self.assertEqual(response.target_endpoint, "127.0.0.1:50052")
        self.assertEqual(len(traffic_station.calls), 1)
        self.assertEqual(len(data_worker_service.requests), 1)

        forwarded_request = data_worker_service.requests[0]
        self.assertEqual(forwarded_request.metadata["payload_key"], "payload_value")
        self.assertEqual(forwarded_request.metadata["gateway_request_id"], "req-123")
        self.assertEqual(forwarded_request.metadata["gateway_trace_id"], "trace-456")
        self.assertIn("gateway_auth_context", forwarded_request.metadata)
        self.assertIn("principal-1", forwarded_request.metadata["gateway_auth_context"])

        payload_body = json.loads(response.payload)
        self.assertEqual(payload_body["status"], "stored")
        self.assertEqual(payload_body["request"]["event_id"], str(request.event_id))
        self.assertEqual(payload_body["record"]["species_name"], "sparrow")

        self.assertEqual(response.metadata["record_id"], str(fake_record.record_id))
        self.assertEqual(response.metadata["stage_a_reason"], "server_assist_not_required")

    async def test_forward_business_rejects_unsupported_operation(self) -> None:
        request = build_edge_event_request()
        payload = {
            "event_id": str(request.event_id),
            "trace_id": str(request.trace_id),
            "context": {
                "device_id": request.context.device_id,
                "device_name": request.context.device_name,
                "location_name": request.context.location_name,
                "trigger_type": request.context.trigger_type,
                "sensor_snapshot": request.context.sensor_snapshot,
                "environment_snapshot": {
                    "temperature_c": 21.5,
                    "humidity_pct": 60,
                    "source": "mock",
                    "sensor_snapshot": {},
                    "captured_at_ms": 1700000000000,
                },
                "captured_at_ms": request.context.captured_at_ms,
            },
            "image": {
                "image_id": request.image.image_id,
                "format": request.image.format,
                "width": request.image.width,
                "height": request.image.height,
                "checksum_sha256": request.image.checksum_sha256,
            },
            "local_inference": None,
            "requires_server_assist": False,
            "metadata": {"payload_key": "payload_value"},
            "image_b64": "",
        }

        data_worker_service = FakeDataWorkerService(
            EdgeEventProcessingResult(
                request=request,
                envelope=SimpleNamespace(
                    event_id=request.event_id,
                    device_entity_id=UUID(request.context.device_id),
                    device_name=request.context.device_name,
                ),
                processing_source="edge",
                stage_a_enter_stage_b=True,
                stage_a_reason="server_assist_not_required",
                monitoring_record=None,
            )
        )
        traffic_station = FakeTrafficStation()
        servicer = BusinessForwardServicer(
            traffic_station=traffic_station,
            data_worker_service=data_worker_service,
            expected_service_name="data_worker",
        )

        grpc_request = business_forward_pb2.BusinessForwardRequest(
            route_key="business.forward.generic",
            operation="edge.events.unknown",
            flow_category="business_forward",
            source_service="gateway",
            target_service_type="internal_service",
            target_service_name="data_worker",
            target_endpoint="127.0.0.1:50052",
            request_id="req-123",
            trace_id="trace-456",
            payload=json.dumps(payload, ensure_ascii=False),
        )

        response = await servicer.ForwardBusiness(grpc_request, None)

        self.assertFalse(response.accepted)
        self.assertEqual(response.status, "rejected")
        self.assertEqual(response.error_code, "invalid_request")
        self.assertIn("unsupported business operation", response.error_message)
        self.assertEqual(len(traffic_station.calls), 0)
        self.assertEqual(len(data_worker_service.requests), 0)
