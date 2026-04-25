# pyright: reportAttributeAccessIssue=false
from __future__ import annotations

import json
import logging
from typing import Any

from google.protobuf import json_format
from grpc import aio

from src.gen.business.v1 import business_forward_pb2 as business_forward_pb2
from src.gen.business.v1 import business_forward_pb2_grpc as business_forward_pb2_grpc
from src.iface.business.data_worker_svc import (
    IDataWorkerService,
    EdgeEventProcessingResult,
)
from src.iface.communication.routing_contract import FlowRouteInput
from src.iface.communication.traffic_station import (
    InboundTrafficRequest,
    ITrafficStation,
)
from src.models.business.event_req_dto import EdgeEventUploadRequest
from src.services.communication.routing_payload_pipeline_svc import (
    BUSINESS_FORWARD_ROUTE_KEY,
)


LOGGER = logging.getLogger(__name__)
BUSINESS_FORWARD_PATH = "/bms.business.v1.BusinessForwardService/ForwardBusiness"
BUSINESS_FORWARD_OPERATION = "edge.events.upload"
EXPECTED_TARGET_SERVICE_TYPE = "internal_service"


class BusinessForwardServicer(business_forward_pb2_grpc.BusinessForwardServiceServicer):
    """data_worker 业务通道 gRPC 上层适配器。"""

    def __init__(
        self,
        *,
        traffic_station: ITrafficStation,
        data_worker_service: IDataWorkerService,
        expected_service_name: str = "data_worker",
    ) -> None:
        if traffic_station is None:
            raise ValueError("traffic station is required")
        if data_worker_service is None:
            raise ValueError("data worker service is required")

        normalized_expected_service_name = (expected_service_name or "").strip()
        if not normalized_expected_service_name:
            raise ValueError("expected service name is required")

        self._traffic_station = traffic_station
        self._data_worker_service = data_worker_service
        self._expected_service_name = normalized_expected_service_name

    async def ForwardBusiness(
        self,
        request: business_forward_pb2.BusinessForwardRequest,
        context: aio.ServicerContext,
    ) -> business_forward_pb2.BusinessForwardResponse:
        if request is None:
            return self._build_failure_response(
                request=None,
                error_code="invalid_request",
                error_message="business forward request is required",
            )

        try:
            self._validate_request_envelope(request)
            flow = self._build_flow_input(request)
            decision = await self._traffic_station.handle_inbound(
                InboundTrafficRequest(
                    flow=flow,
                    headers=dict(request.headers or {}),
                    payload=request.payload,
                )
            )
            if not decision.accepted:
                reason = (decision.reason or "").strip() or "route_rejected"
                return self._build_failure_response(
                    request=request,
                    error_code="route_rejected",
                    error_message=reason,
                    route_profile=decision.profile,
                )

            edge_request = self._decode_edge_event_request(request)
            edge_request = self._merge_gateway_context(edge_request, request)

            result = await self._data_worker_service.handle_edge_upload(edge_request)
            return self._build_success_response(
                request=request,
                route_profile=decision.profile,
                result=result,
            )
        except json.JSONDecodeError as exc:
            LOGGER.warning("business forward payload decode failed: %s", exc)
            return self._build_failure_response(
                request=request,
                error_code="invalid_payload",
                error_message=str(exc),
            )
        except ValueError as exc:
            LOGGER.warning("business forward request rejected: %s", exc)
            return self._build_failure_response(
                request=request,
                error_code="invalid_request",
                error_message=str(exc),
            )
        except Exception as exc:  # noqa: BLE001
            LOGGER.exception("business forward handling failed")
            return self._build_failure_response(
                request=request,
                error_code="internal_error",
                error_message=str(exc),
            )

    def _validate_request_envelope(
        self,
        request: business_forward_pb2.BusinessForwardRequest,
    ) -> None:
        route_key = self._normalized(request.route_key)
        if route_key != BUSINESS_FORWARD_ROUTE_KEY:
            raise ValueError("unsupported business route key")

        flow_category = self._normalized(request.flow_category)
        if flow_category != "business_forward":
            raise ValueError("unsupported flow category")

        operation = self._normalized(request.operation)
        if operation != BUSINESS_FORWARD_OPERATION:
            raise ValueError("unsupported business operation")

        target_service_type = self._normalized(request.target_service_type)
        if target_service_type != EXPECTED_TARGET_SERVICE_TYPE:
            raise ValueError("unsupported target service type")

        target_service_name = self._normalized(request.target_service_name)
        if target_service_name != self._normalized(self._expected_service_name):
            raise ValueError("unsupported target service name")

        if not self._normalized(request.target_endpoint):
            raise ValueError("target endpoint is required")

        if not self._normalized(request.request_id):
            raise ValueError("request_id is required")

        if not self._normalized(request.trace_id):
            raise ValueError("trace_id is required")

        if not self._normalized(request.payload):
            raise ValueError("business payload is required")

    def _build_flow_input(
        self,
        request: business_forward_pb2.BusinessForwardRequest,
    ) -> FlowRouteInput:
        metadata = dict(request.metadata or {})
        metadata.update(
            {
                "target_service": self._expected_service_name,
                "target_endpoint": self._normalized(request.target_endpoint),
                "operation": self._normalized(request.operation),
                "gateway_request_id": self._normalized(request.request_id),
                "gateway_trace_id": self._normalized(request.trace_id),
                "trusted_internal_call": "true",
            }
        )

        return FlowRouteInput(
            route_key=BUSINESS_FORWARD_ROUTE_KEY,
            transport="grpc",
            method="POST",
            path=BUSINESS_FORWARD_PATH,
            source_service=self._normalized(request.source_service),
            target_service_hint=self._expected_service_name,
            metadata=metadata,
        )

    def _decode_edge_event_request(
        self,
        request: business_forward_pb2.BusinessForwardRequest,
    ) -> EdgeEventUploadRequest:
        return EdgeEventUploadRequest.model_validate_json(request.payload)

    def _merge_gateway_context(
        self,
        edge_request: EdgeEventUploadRequest,
        request: business_forward_pb2.BusinessForwardRequest,
    ) -> EdgeEventUploadRequest:
        metadata = dict(edge_request.metadata or {})
        metadata["gateway_request_id"] = self._normalized(request.request_id)
        metadata["gateway_trace_id"] = self._normalized(request.trace_id)
        metadata["gateway_route_key"] = self._normalized(request.route_key)
        metadata["gateway_operation"] = self._normalized(request.operation)
        metadata["gateway_flow_category"] = self._normalized(request.flow_category)
        metadata["gateway_source_service"] = self._normalized(request.source_service)
        metadata["gateway_target_service_type"] = self._normalized(
            request.target_service_type
        )
        metadata["gateway_target_service_name"] = self._normalized(
            request.target_service_name
        )
        metadata["gateway_target_endpoint"] = self._normalized(request.target_endpoint)
        metadata["gateway_headers"] = self._stringify_json(request.headers)
        metadata["gateway_metadata"] = self._stringify_json(request.metadata)

        if request.HasField("auth_context"):
            metadata["gateway_auth_context"] = self._stringify_json(
                json_format.MessageToDict(
                    request.auth_context,
                    preserving_proto_field_name=True,
                )
            )

        return edge_request.model_copy(update={"metadata": metadata})

    def _build_success_response(
        self,
        *,
        request: business_forward_pb2.BusinessForwardRequest,
        route_profile,
        result: EdgeEventProcessingResult,
    ) -> business_forward_pb2.BusinessForwardResponse:
        status = "stored" if result.monitoring_record is not None else "dropped"
        payload = self._build_result_payload(result, status=status)
        metadata = self._build_result_metadata(
            request=request,
            route_profile=route_profile,
            result=result,
            status=status,
        )
        return business_forward_pb2.BusinessForwardResponse(
            accepted=True,
            status=status,
            route_key=self._normalized(request.route_key),
            operation=self._normalized(request.operation),
            target_service_name=self._normalized(request.target_service_name),
            target_endpoint=self._normalized(request.target_endpoint),
            payload=payload,
            metadata=metadata,
            error_code="",
            error_message="",
        )

    def _build_failure_response(
        self,
        *,
        request: business_forward_pb2.BusinessForwardRequest,
        error_code: str,
        error_message: str,
        route_profile: Any | None = None,
    ) -> business_forward_pb2.BusinessForwardResponse:
        request = request or business_forward_pb2.BusinessForwardRequest()
        metadata = self._build_failure_metadata(
            request=request,
            error_code=error_code,
            error_message=error_message,
            route_profile=route_profile,
        )
        payload = json.dumps(
            {
                "status": "rejected",
                "error_code": error_code,
                "error_message": error_message,
            },
            ensure_ascii=False,
            sort_keys=True,
            default=str,
        )
        return business_forward_pb2.BusinessForwardResponse(
            accepted=False,
            status="rejected",
            route_key=self._normalized(request.route_key),
            operation=self._normalized(request.operation),
            target_service_name=self._normalized(request.target_service_name)
            or self._expected_service_name,
            target_endpoint=self._normalized(request.target_endpoint),
            payload=payload,
            metadata=metadata,
            error_code=error_code,
            error_message=error_message,
        )

    def _build_result_payload(
        self,
        result: EdgeEventProcessingResult,
        *,
        status: str,
    ) -> str:
        payload: dict[str, Any] = {
            "status": status,
            "request": {
                "event_id": str(result.request.event_id),
                "trace_id": str(result.request.trace_id),
                "processing_source": result.processing_source,
                "stage_a_reason": result.stage_a_reason,
                "stage_a_enter_stage_b": result.stage_a_enter_stage_b,
            },
            "envelope": {
                "event_id": str(result.envelope.event_id),
                "device_entity_id": str(result.envelope.device_entity_id),
                "device_name": result.envelope.device_name,
            },
        }

        if result.monitoring_record is not None:
            payload["record"] = self._serialize_record(result.monitoring_record)
        else:
            payload["reason"] = result.stage_a_reason

        return json.dumps(payload, ensure_ascii=False, sort_keys=True, default=str)

    def _build_result_metadata(
        self,
        *,
        request: business_forward_pb2.BusinessForwardRequest,
        route_profile: Any | None,
        result: EdgeEventProcessingResult,
        status: str,
    ) -> dict[str, str]:
        metadata: dict[str, str] = {
            "route_key": self._normalized(request.route_key),
            "flow_category": self._normalized(request.flow_category),
            "operation": self._normalized(request.operation),
            "target_service_type": self._normalized(request.target_service_type),
            "target_service_name": self._normalized(request.target_service_name),
            "target_endpoint": self._normalized(request.target_endpoint),
            "request_id": self._normalized(request.request_id),
            "trace_id": self._normalized(request.trace_id),
            "status": status,
            "processing_source": result.processing_source,
            "stage_a_reason": result.stage_a_reason,
            "stage_a_enter_stage_b": str(result.stage_a_enter_stage_b),
            "gateway_request_id": self._normalized(request.request_id),
            "gateway_trace_id": self._normalized(request.trace_id),
        }

        if route_profile is not None:
            metadata["route_profile_flow_category"] = self._normalized(
                getattr(route_profile, "flow_category", "")
            )
            metadata["route_profile_target_service_type"] = self._normalized(
                getattr(route_profile, "target_service_type", "")
            )
            metadata["route_profile_target_service_name"] = self._normalized(
                getattr(route_profile, "target_service_name", "")
            )
            metadata["route_profile_target_endpoint"] = self._normalized(
                getattr(route_profile, "target_endpoint", "")
            )

        if result.monitoring_record is not None:
            record = result.monitoring_record
            metadata["record_id"] = self._normalized(self._record_identifier(record))
            metadata["device_entity_id"] = self._normalized(
                getattr(record, "device_entity_id", "")
            )
            metadata["source_event_id"] = self._normalized(
                getattr(record, "source_event_id", "")
            )
            metadata["species_name"] = self._normalized(
                getattr(record, "species_name", "")
            )
            metadata["scientific_name"] = self._normalized(
                getattr(record, "scientific_name", "")
            )
            metadata["confidence"] = str(getattr(record, "confidence", 0.0))

        return metadata

    def _build_failure_metadata(
        self,
        *,
        request: business_forward_pb2.BusinessForwardRequest,
        error_code: str,
        error_message: str,
        route_profile: Any | None,
    ) -> dict[str, str]:
        metadata = self._build_result_metadata(
            request=request,
            route_profile=route_profile,
            result=EdgeEventProcessingResult(  # type: ignore[arg-type]
                request=self._empty_edge_request(),
                envelope=self._empty_envelope(),
                processing_source="data_worker",
                stage_a_enter_stage_b=False,
                stage_a_reason=error_message,
                monitoring_record=None,
            ),
            status="rejected",
        )
        metadata["error_code"] = error_code
        metadata["error_message"] = error_message
        return metadata

    @staticmethod
    def _empty_edge_request() -> EdgeEventUploadRequest:
        return EdgeEventUploadRequest.model_validate(
            {
                "event_id": "00000000-0000-0000-0000-000000000000",
                "trace_id": "00000000-0000-0000-0000-000000000000",
                "context": {
                    "device_id": "00000000-0000-0000-0000-000000000000",
                    "device_name": "",
                    "location_name": "",
                    "trigger_type": "manual",
                    "sensor_snapshot": {},
                    "environment_snapshot": None,
                    "captured_at_ms": 0,
                },
                "image": {
                    "image_id": "",
                    "format": "jpg",
                    "width": None,
                    "height": None,
                    "checksum_sha256": None,
                },
                "local_inference": None,
                "requires_server_assist": False,
                "metadata": {},
                "image_b64": "",
            }
        )

    @staticmethod
    def _empty_envelope() -> Any:
        class _Envelope:
            event_id = "00000000-0000-0000-0000-000000000000"
            device_entity_id = "00000000-0000-0000-0000-000000000000"
            device_name = ""

        return _Envelope()

    @staticmethod
    def _record_identifier(record: Any) -> Any:
        if hasattr(record, "record_id"):
            return getattr(record, "record_id")
        return getattr(record, "id", "")

    @staticmethod
    def _serialize_record(record: Any) -> dict[str, Any]:
        if hasattr(record, "model_dump"):
            try:
                serialized = dict(record.model_dump(mode="json"))
            except TypeError:
                serialized = dict(record.model_dump())
        else:
            serialized = {
                key: value
                for key, value in vars(record).items()
                if not key.startswith("_")
            }

        serialized.setdefault(
            "record_id", str(BusinessForwardServicer._record_identifier(record))
        )
        return serialized

    @staticmethod
    def _normalized(value: Any) -> str:
        return str(value or "").strip()

    @staticmethod
    def _stringify_json(value: Any) -> str:
        return json.dumps(value or {}, ensure_ascii=False, sort_keys=True, default=str)
