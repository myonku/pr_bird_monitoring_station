from __future__ import annotations

from src.interface import IHttpTransportClient, IUploader
from src.models.models import EdgeEvent


class UnifiedUploader(IUploader):
    """HTTP 统一上传器。"""

    def __init__(self, transport_client: IHttpTransportClient):
        self.client = transport_client

    def upload(self, event: EdgeEvent) -> bool:
        try:
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
                    "detection": {
                        "success": event.local_inference.detection.success,
                        "reason": event.local_inference.detection.reason,
                        "latency_ms": event.local_inference.detection.latency_ms,
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
                            "topk": [
                                {"label": hit.label, "confidence": hit.confidence}
                                for hit in event.local_inference.classification.topk
                            ],
                        }
                        if event.local_inference.classification is not None
                        else None
                    ),
                }

            payload = {
                "event_id": event.event_id,
                "trace_id": event.trace_id,
                "requires_server_assist": event.requires_server_assist,
                "context": {
                    "device_id": event.context.device_id,
                    "trigger_type": event.context.trigger_type,
                    "sensor_snapshot": event.context.sensor_snapshot,
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
            return self.client.send(payload, image_bytes=event.image.bytes_data)
        except Exception:
            return False

    def is_connection_ready(self) -> bool:
        return self.client.healthcheck()
