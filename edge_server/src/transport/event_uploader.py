import base64
import json
import time
from urllib import request
from urllib.error import HTTPError, URLError

from src.iface.auth_interface import IEdgeAuthCoordinator
from src.iface.upload_interface import IEdgeEventUploadCoordinator
from src.models.workflow.workflow import EdgeEvent


class EdgeEventHttpUploadCoordinator(IEdgeEventUploadCoordinator):
    """事件流 HTTP 上传协调器。"""

    def __init__(
        self,
        upload_url: str,
        healthcheck_url: str,
        timeout_sec: float = 3.0,
        auth_coordinator: IEdgeAuthCoordinator | None = None,
        healthcheck_cache_ttl_sec: float = 1.0,
    ) -> None:
        self.upload_url = upload_url
        self.healthcheck_url = healthcheck_url
        self.timeout_sec = timeout_sec
        self.auth_coordinator = auth_coordinator
        self.healthcheck_cache_ttl_sec = max(0.0, float(healthcheck_cache_ttl_sec))
        self._healthcheck_cache_until = 0.0
        self._healthcheck_cache_value: bool | None = None

    def _cache_healthcheck(self, value: bool) -> bool:
        if self.healthcheck_cache_ttl_sec <= 0:
            self._healthcheck_cache_value = None
            self._healthcheck_cache_until = 0.0
            return value

        self._healthcheck_cache_value = value
        self._healthcheck_cache_until = (
            time.monotonic() + self.healthcheck_cache_ttl_sec
        )
        return value

    @staticmethod
    def _build_environment_snapshot(
        environment_snapshot,
    ) -> dict | None:
        if environment_snapshot is None:
            return None
        return {
            "temperature_c": environment_snapshot.temperature_c,
            "humidity_pct": environment_snapshot.humidity_pct,
            "source": environment_snapshot.source,
            "sensor_snapshot": environment_snapshot.sensor_snapshot,
            "captured_at_ms": environment_snapshot.captured_at_ms,
        }

    @staticmethod
    def _build_payload(event: EdgeEvent) -> dict:
        local_inference = None
        if event.local_inference is not None:
            local_inference = {
                "success": event.local_inference.success,
                "stage": event.local_inference.stage,
                "reason": event.local_inference.reason,
                "crop_applied": event.local_inference.crop_applied,
                "crop_box": event.local_inference.crop_box,
                "detector_model_version": event.local_inference.detector_model_version,
                "classifier_model_version": event.local_inference.classifier_model_version,
                "detector_model_signature": event.local_inference.detector_model_signature,
                "classifier_model_signature": event.local_inference.classifier_model_signature,
                "detection": {
                    "success": event.local_inference.detection.success,
                    "reason": event.local_inference.detection.reason,
                    "latency_ms": event.local_inference.detection.latency_ms,
                    "model_signature": event.local_inference.detection.model_signature,
                    "boxes": [
                        {
                            "label": box.label,
                            "confidence": box.confidence,
                            "x1": box.x1,
                            "y1": box.y1,
                            "x2": box.x2,
                            "y2": box.y2,
                        }
                        for box in event.local_inference.detection.boxes
                    ],
                },
                "classification": (
                    {
                        "success": event.local_inference.classification.success,
                        "top1_label": event.local_inference.classification.top1_label,
                        "top1_confidence": event.local_inference.classification.top1_confidence,
                        "latency_ms": event.local_inference.classification.latency_ms,
                        "reason": event.local_inference.classification.reason,
                        "model_signature": event.local_inference.classification.model_signature,
                        "topk": [
                            {"label": hit.label, "confidence": hit.confidence}
                            for hit in event.local_inference.classification.topk
                        ],
                    }
                    if event.local_inference.classification is not None
                    else None
                ),
            }

        return {
            "event_id": event.event_id,
            "trace_id": event.trace_id,
            "requires_server_assist": event.requires_server_assist,
            "context": {
                "device_id": event.context.device_id,
                "device_name": event.context.device_name,
                "location_name": event.context.location_name,
                "trigger_type": event.context.trigger_type,
                "sensor_snapshot": event.context.sensor_snapshot,
                "environment_snapshot": EdgeEventHttpUploadCoordinator._build_environment_snapshot(
                    event.context.environment_snapshot
                ),
                "captured_at_ms": event.context.captured_at_ms,
            },
            "image": {
                "image_id": event.image.image_id,
                "format": event.image.format,
                "width": event.image.width,
                "height": event.image.height,
                "checksum_sha256": event.image.checksum_sha256,
            },
            "local_inference": local_inference,
            "metadata": event.metadata,
        }

    def _resolve_auth_headers(self) -> dict[str, str]:
        if self.auth_coordinator is not None:
            return self.auth_coordinator.get_auth_headers().to_http_headers()
        return {}

    def _build_headers(self) -> dict[str, str]:
        headers = {
            "Content-Type": "application/json",
        }
        headers.update(self._resolve_auth_headers())
        return headers

    def _upload_once(self, data: bytes, headers: dict[str, str]) -> bool:
        req = request.Request(
            self.upload_url,
            data=data,
            headers=headers,
            method="POST",
        )
        with request.urlopen(req, timeout=self.timeout_sec) as resp:
            return 200 <= resp.status < 300

    def upload_event(self, event: EdgeEvent) -> bool:
        payload = self._build_payload(event)
        body = {
            **payload,
            "image_b64": base64.b64encode(event.image.bytes_data).decode("ascii"),
        }
        data = json.dumps(body, ensure_ascii=False).encode("utf-8")

        try:
            headers = self._build_headers()
        except Exception:
            return False

        try:
            return self._upload_once(data, headers=headers)
        except HTTPError as err:
            if self.auth_coordinator is None or err.code not in (401, 403):
                return False
            body_text = ""
            try:
                body_text = err.read().decode("utf-8", errors="ignore")
            except Exception:
                body_text = ""

            try:
                self.auth_coordinator.on_unauthorized(err.code, body_text)
                retry_headers = self._build_headers()
                return self._upload_once(data, headers=retry_headers)
            except (HTTPError, URLError, TimeoutError, ValueError):
                return False
        except (URLError, TimeoutError):
            return False

    def is_upload_endpoint_ready(self) -> bool:
        now = time.monotonic()
        if (
            self._healthcheck_cache_value is not None
            and now < self._healthcheck_cache_until
        ):
            return self._healthcheck_cache_value

        try:
            headers = self._resolve_auth_headers()
        except Exception:
            return self._cache_healthcheck(False)

        req = request.Request(self.healthcheck_url, headers=headers, method="GET")
        try:
            with request.urlopen(req, timeout=self.timeout_sec) as resp:
                return self._cache_healthcheck(200 <= resp.status < 300)
        except (HTTPError, URLError, TimeoutError):
            return self._cache_healthcheck(False)
