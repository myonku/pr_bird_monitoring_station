# pyright: reportAttributeAccessIssue=false
from __future__ import annotations

import json
import logging
from typing import Any

from grpc import aio

from src.gen.business.v1 import business_forward_pb2 as _bfpb2
from src.gen.business.v1 import business_forward_pb2_grpc
from src.iface.business.chat_service import IChatService
from src.iface.communication.routing_contract import FlowRouteInput
from src.iface.communication.traffic_station import (
    InboundTrafficRequest,
    ITrafficStation,
)
from src.models.business.chat_req_dto import (
    ChatSendRequest,
    ChatSessionCreateRequest,
    ChatSessionDeleteRequest,
    ChatSessionGetRequest,
    ChatSessionListRequest,
)

LOGGER = logging.getLogger(__name__)
BUSINESS_FORWARD_PATH = "/bms.business.v1.BusinessForwardService/ForwardBusiness"
BUSINESS_FORWARD_ROUTE_KEY = "business.forward.generic"
EXPECTED_TARGET_SERVICE_TYPE = "internal_service"


class BusinessForwardServicer(business_forward_pb2_grpc.BusinessForwardServiceServicer):
    """bms_copilot 业务通道 gRPC 上层适配器�?

    将统一业务请求�?operation 分发�?IChatService 对应方法�?
    """

    def __init__(
        self,
        *,
        traffic_station: ITrafficStation,
        chat_service: IChatService,
        expected_service_name: str = "bms_copilot",
    ) -> None:
        if traffic_station is None:
            raise ValueError("traffic station is required")
        if chat_service is None:
            raise ValueError("chat service is required")

        self._traffic_station = traffic_station
        self._chat_service = chat_service
        self._expected_service_name = (expected_service_name or "").strip()

    async def ForwardBusiness(
        self,
        request: Any,
        context: aio.ServicerContext,
    ) -> Any:
        if request is None:
            return self._failure(None, "invalid_request", "request is required")

        try:
            self._validate_envelope(request)
            flow = self._build_flow(request)
            decision = await self._traffic_station.handle_inbound(
                InboundTrafficRequest(
                    flow=flow,
                    headers=dict(request.headers or {}),
                    payload=request.payload,
                )
            )
            if not decision.accepted:
                reason = (decision.reason or "").strip() or "route_rejected"
                return self._failure(request, "route_rejected", reason)

            payload = await self._dispatch(request)
            return self._success(request, payload)
        except json.JSONDecodeError as exc:
            return self._failure(request, "invalid_payload", str(exc))
        except ValueError as exc:
            return self._failure(request, "invalid_request", str(exc))
        except Exception as exc:
            LOGGER.exception("business forward failed")
            return self._failure(request, "internal_error", str(exc))

    async def _dispatch(self, request: Any) -> dict[str, Any]:
        op = (request.operation or "").strip().lower()

        if op == "client.chat.send":
            req = _decode(request.payload, ChatSendRequest)
            result = await self._chat_service.send_message(req)
            return _dump(result)

        if op == "client.chat.sessions.list":
            req = _decode(request.payload, ChatSessionListRequest)
            result = await self._chat_service.list_sessions(req)
            return _dump(result)

        if op == "client.chat.sessions.detail":
            req = _decode(request.payload, ChatSessionGetRequest)
            result = await self._chat_service.get_session(req)
            return _dump(result)

        if op == "client.chat.sessions.delete":
            req = _decode(request.payload, ChatSessionDeleteRequest)
            result = await self._chat_service.delete_session(req)
            return _dump(result)

        if op == "client.chat.sessions.create":
            req = _decode(request.payload, ChatSessionCreateRequest)
            result = await self._chat_service.create_session(req)
            return _dump(result)

        raise ValueError(f"unsupported operation: {op}")

    def _validate_envelope(self, request: Any) -> None:
        _require(request.route_key, BUSINESS_FORWARD_ROUTE_KEY, "route_key")
        _require(request.flow_category, "business_forward", "flow_category")
        _require(
            request.target_service_type,
            EXPECTED_TARGET_SERVICE_TYPE,
            "target_service_type",
        )
        _require(
            request.target_service_name,
            self._expected_service_name,
            "target_service_name",
        )
        _require(request.request_id, None, "request_id")
        _require(request.payload, None, "payload")

    def _build_flow(self, request: Any) -> FlowRouteInput:
        metadata = dict(request.metadata or {})
        metadata.update(
            {
                "target_service": self._expected_service_name,
                "target_endpoint": (request.target_endpoint or "").strip(),
                "operation": (request.operation or "").strip(),
                "gateway_request_id": (request.request_id or "").strip(),
                "gateway_trace_id": (request.trace_id or "").strip(),
                "trusted_internal_call": "true",
            }
        )
        return FlowRouteInput(
            route_key=BUSINESS_FORWARD_ROUTE_KEY,
            transport="grpc",
            method="POST",
            path=BUSINESS_FORWARD_PATH,
            source_service=(request.source_service or "").strip(),
            target_service_hint=self._expected_service_name,
            metadata=metadata,
        )

    def _success(
        self,
        request: Any,
        payload: dict[str, Any],
    ) -> Any:
        resp_cls = _bfpb2.BusinessForwardResponse
        return resp_cls(
            accepted=True,
            status="ok",
            route_key=(request.route_key or "").strip(),
            operation=(request.operation or "").strip(),
            target_service_name=self._expected_service_name,
            target_endpoint=(request.target_endpoint or "").strip(),
            payload=json.dumps(payload, ensure_ascii=False, default=str),
            error_code="",
            error_message="",
        )

    def _failure(
        self,
        request: Any | None,
        code: str,
        message: str,
    ) -> Any:
        req_cls = _bfpb2.BusinessForwardRequest
        resp_cls = _bfpb2.BusinessForwardResponse
        r = request or req_cls()
        return resp_cls(
            accepted=False,
            status="rejected",
            route_key=(r.route_key or "").strip(),
            operation=(r.operation or "").strip(),
            target_service_name=self._expected_service_name,
            target_endpoint=(r.target_endpoint or "").strip(),
            payload=json.dumps(
                {"error_code": code, "error_message": message},
                ensure_ascii=False,
                default=str,
            ),
            error_code=code,
            error_message=message,
        )


def _decode(payload: str, model: type[Any]) -> Any:
    from msgspec import json as msgspec_json

    return msgspec_json.decode(payload.encode("utf-8"), type=model)


def _dump(obj: Any) -> Any:
    model_dump = getattr(obj, "model_dump", None)
    if callable(model_dump):
        return model_dump()
    from msgspec import to_builtins

    return to_builtins(obj)


def _require(value: str, expected: str | None, name: str) -> None:
    if not (value or "").strip():
        raise ValueError(f"{name} is required")
    if expected is not None and (value or "").strip() != expected:
        raise ValueError(f"unexpected {name}: {value}")
