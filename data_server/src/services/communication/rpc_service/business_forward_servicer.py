# pyright: reportAttributeAccessIssue=false
from __future__ import annotations

import json
import logging
from typing import Any

from msgspec import json as msgspec_json
from msgspec import to_builtins
from grpc import aio

from src.models.business.client_resp_dto import ClientUserProfileResponse
from src.gen.business.v1 import business_forward_pb2
from src.gen.business.v1 import business_forward_pb2_grpc
from src.iface.business.data_server_svc import IDataServerService
from src.iface.communication.routing_contract import FlowRouteInput
from src.iface.communication.traffic_station import (
    InboundTrafficRequest,
    ITrafficStation,
)
from src.models.business.client_req_dto import (
    ClientHomeSnapshotRequest,
    ClientRangeSummaryRequest,
    ClientRecordsCursorRequest,
    ClientRecordStationOptionsRequest,
    ClientRegisterRequest,
    ClientUserProfileRequest,
    ClientWeeklyTrendRequest,
)
from src.services.communication.routing_payload_pipeline_svc import (
    BUSINESS_FORWARD_ROUTE_KEY,
)


LOGGER = logging.getLogger(__name__)
BUSINESS_FORWARD_PATH = "/bms.business.v1.BusinessForwardService/ForwardBusiness"
BUSINESS_FORWARD_OPERATION = "client.business.forward"
EXPECTED_TARGET_SERVICE_TYPE = "internal_service"


class BusinessForwardServicer(business_forward_pb2_grpc.BusinessForwardServiceServicer):
    """data_server 业务通道 gRPC 上层适配器。"""

    def __init__(
        self,
        *,
        traffic_station: ITrafficStation,
        data_server_service: IDataServerService,
        expected_service_name: str = "data_server",
    ) -> None:
        if traffic_station is None:
            raise ValueError("traffic station is required")
        if data_server_service is None:
            raise ValueError("data server service is required")

        normalized_expected_service_name = (expected_service_name or "").strip()
        if not normalized_expected_service_name:
            raise ValueError("expected service name is required")

        self._traffic_station = traffic_station
        self._data_server_service = data_server_service
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

            result_payload = await self._dispatch_operation(request)
            return self._build_success_response(
                request=request,
                route_profile=decision.profile,
                result_payload=result_payload,
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

    async def _dispatch_operation(
        self,
        request: business_forward_pb2.BusinessForwardRequest,
    ) -> Any:
        """根据 operation 字段分发到 IDataServerService 对应方法。

        返回原始的序列化结果（dict 或 list），不再包裹 status/data 层，
        gRPC BusinessForwardResponse.payload 直接承载业务数据 JSON。
        """
        operation = (request.operation or "").strip().lower()

        if operation in ("client.users.register",):
            req = self._decode_msgspec_payload(request.payload, ClientRegisterRequest)
            result = await self._data_server_service.register_user(req)
            return self._serialize_result(result)

        if operation in ("client.users.profile",):
            req = self._decode_msgspec_payload(request.payload, ClientUserProfileRequest)
            result = await self._data_server_service.get_user_profile(req)
            if result is None:
                return self._serialize_result(
                    ClientUserProfileResponse(
                        user_id="",
                        username="",
                        display_name="",
                        name="",
                        role="",
                        email="",
                        phone="",
                        avatar_b64="",
                    )
                )
            return self._serialize_result(result)

        if operation in ("client.home.summary",):
            req = None
            if request.payload:
                req = self._decode_msgspec_payload(request.payload, ClientHomeSnapshotRequest)
            result = await self._data_server_service.get_dashboard_snapshot(req)
            return self._serialize_result(result)

        if operation in ("client.records.list", "client.records.cursor"):
            req = self._decode_msgspec_payload(request.payload, ClientRecordsCursorRequest)
            result = await self._data_server_service.list_records_by_cursor(req)
            return self._serialize_result(result)

        if operation in ("client.records.stations", "client.records.station_options"):
            req = None
            if request.payload:
                req = self._decode_msgspec_payload(
                    request.payload,
                    ClientRecordStationOptionsRequest,
                )
            result = await self._data_server_service.list_record_station_options(req)
            return self._serialize_result(result)

        if operation in ("client.stats.weekly-trend", "client.stats.weekly_trend"):
            req = self._decode_msgspec_payload(request.payload, ClientWeeklyTrendRequest)
            result = await self._data_server_service.get_weekly_trend(req)
            return self._serialize_result(result)

        if operation in ("client.stats.range-summary", "client.stats.range_summary"):
            req = self._decode_msgspec_payload(request.payload, ClientRangeSummaryRequest)
            result = await self._data_server_service.get_range_summary(req)
            return self._serialize_result(result)

        raise ValueError(f"unsupported business operation: {operation}")

    @staticmethod
    def _decode_msgspec_payload(payload: str, model_type: type[Any]) -> Any:
        return msgspec_json.decode(payload.encode("utf-8"), type=model_type)

    @staticmethod
    def _serialize_result(result: Any) -> Any:
        if result is None:
            return {}

        model_dump = getattr(result, "model_dump", None)
        if callable(model_dump):
            return model_dump()

        return to_builtins(result)

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

    def _build_success_response(
        self,
        *,
        request: business_forward_pb2.BusinessForwardRequest,
        route_profile: Any | None,
        result_payload: Any,
    ) -> business_forward_pb2.BusinessForwardResponse:
        payload = json.dumps(result_payload, ensure_ascii=False, sort_keys=True, default=str)
        metadata = self._build_result_metadata(
            request=request,
            route_profile=route_profile,
            status="ok",
        )
        return business_forward_pb2.BusinessForwardResponse(
            accepted=True,
            status="ok",
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

    def _build_result_metadata(
        self,
        *,
        request: business_forward_pb2.BusinessForwardRequest,
        route_profile: Any | None,
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
            status="rejected",
        )
        metadata["error_code"] = error_code
        metadata["error_message"] = error_message
        return metadata

    @staticmethod
    def _normalized(value: Any) -> str:
        return str(value or "").strip()

    @staticmethod
    def _stringify_json(value: Any) -> str:
        return json.dumps(value or {}, ensure_ascii=False, sort_keys=True, default=str)
