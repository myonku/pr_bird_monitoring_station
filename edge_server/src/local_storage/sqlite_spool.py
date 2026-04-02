import json
import time
from collections.abc import Iterable
from dataclasses import asdict
from typing import Any, Literal, cast

from src.iface.workflow_interface import ISpoolStorage
from src.local_storage.sqlite_client import SQLiteClient
from src.models.workflow.workflow import (
    CaptureContext,
    ClassificationHit,
    ClassificationResult,
    DetectionBox,
    DetectionResult,
    EdgeEvent,
    ImagePayload,
    TwoStageInferenceResult,
)


class SQLiteSpoolStorage(ISpoolStorage):
    """SQLite 本地缓存实现：网络不稳定时缓存，网络恢复后续传。"""

    def __init__(
        self,
        db_path: str | None = None,
        sqlite_client: SQLiteClient | None = None,
    ) -> None:
        if sqlite_client is None:
            if not db_path:
                raise ValueError("db_path is required when sqlite_client is not provided")
            sqlite_client = SQLiteClient(db_path=db_path)
        self._sqlite = sqlite_client
        self._init_db()

    def _connect(self):
        return self._sqlite.connect()

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS edge_spool_events (
                    record_id TEXT PRIMARY KEY,
                    event_id TEXT NOT NULL,
                    trace_id TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    image_blob BLOB NOT NULL,
                    created_at_ms INTEGER NOT NULL,
                    retry_count INTEGER NOT NULL DEFAULT 0,
                    last_retry_reason TEXT,
                    last_retry_ms INTEGER
                )
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_edge_spool_events_created
                ON edge_spool_events (created_at_ms)
                """
            )
            conn.commit()

    @staticmethod
    def _serialize_event_payload(event: EdgeEvent) -> str:
        payload = asdict(event)
        # 图像二进制单独存储在 BLOB，避免 JSON 体积过大。
        payload["image"]["bytes_data"] = None
        return json.dumps(payload, ensure_ascii=False)

    @staticmethod
    def _parse_infer_stage(
        value: Any,
    ) -> Literal[
        "skipped",
        "detected_only",
        "classified",
        "detector_failed",
        "classifier_failed",
    ]:
        allowed = {
            "skipped",
            "detected_only",
            "classified",
            "detector_failed",
            "classifier_failed",
        }
        if isinstance(value, str) and value in allowed:
            return cast(
                Literal[
                    "skipped",
                    "detected_only",
                    "classified",
                    "detector_failed",
                    "classifier_failed",
                ],
                value,
            )
        return "skipped"

    @staticmethod
    def _parse_trigger_type(
        value: Any,
    ) -> Literal["motion", "scheduled", "manual"]:
        allowed = {"motion", "scheduled", "manual"}
        if isinstance(value, str) and value in allowed:
            return cast(Literal["motion", "scheduled", "manual"], value)
        return "motion"

    @staticmethod
    def _to_detection(payload: dict[str, Any] | None) -> DetectionResult:
        if not payload:
            return DetectionResult(success=False, reason="missing_detection")
        boxes = [
            DetectionBox(
                label=str(item.get("label", "")),
                confidence=float(item.get("confidence", 0.0)),
                x1=float(item.get("x1", 0.0)),
                y1=float(item.get("y1", 0.0)),
                x2=float(item.get("x2", 0.0)),
                y2=float(item.get("y2", 0.0)),
            )
            for item in payload.get("boxes", [])
            if isinstance(item, dict)
        ]
        return DetectionResult(
            success=bool(payload.get("success", False)),
            boxes=boxes,
            latency_ms=(
                int(payload["latency_ms"])
                if payload.get("latency_ms") is not None
                else None
            ),
            reason=(str(payload["reason"]) if payload.get("reason") else None),
            model_signature=(
                str(payload["model_signature"])
                if payload.get("model_signature")
                else None
            ),
        )

    @staticmethod
    def _to_classification(payload: dict[str, Any] | None) -> ClassificationResult | None:
        if payload is None:
            return None

        topk = [
            ClassificationHit(
                label=str(item.get("label", "")),
                confidence=float(item.get("confidence", 0.0)),
            )
            for item in payload.get("topk", [])
            if isinstance(item, dict)
        ]
        return ClassificationResult(
            success=bool(payload.get("success", False)),
            top1_label=(
                str(payload["top1_label"])
                if payload.get("top1_label") is not None
                else None
            ),
            top1_confidence=(
                float(payload["top1_confidence"])
                if payload.get("top1_confidence") is not None
                else None
            ),
            topk=topk,
            latency_ms=(
                int(payload["latency_ms"])
                if payload.get("latency_ms") is not None
                else None
            ),
            reason=(str(payload["reason"]) if payload.get("reason") else None),
            model_signature=(
                str(payload["model_signature"])
                if payload.get("model_signature")
                else None
            ),
        )

    @classmethod
    def _to_local_inference(
        cls, payload: dict[str, Any] | None
    ) -> TwoStageInferenceResult | None:
        if payload is None:
            return None

        detection = cls._to_detection(
            payload.get("detection") if isinstance(payload.get("detection"), dict) else None
        )
        classification_payload = payload.get("classification")
        classification = cls._to_classification(
            classification_payload if isinstance(classification_payload, dict) else None
        )

        return TwoStageInferenceResult(
            success=bool(payload.get("success", False)),
            stage=cls._parse_infer_stage(payload.get("stage")),
            detection=detection,
            classification=classification,
            crop_applied=bool(payload.get("crop_applied", False)),
            crop_box=(
                {
                    "x1": float(payload["crop_box"].get("x1", 0.0)),
                    "y1": float(payload["crop_box"].get("y1", 0.0)),
                    "x2": float(payload["crop_box"].get("x2", 0.0)),
                    "y2": float(payload["crop_box"].get("y2", 0.0)),
                }
                if isinstance(payload.get("crop_box"), dict)
                else None
            ),
            detector_model_version=(
                str(payload["detector_model_version"])
                if payload.get("detector_model_version")
                else None
            ),
            classifier_model_version=(
                str(payload["classifier_model_version"])
                if payload.get("classifier_model_version")
                else None
            ),
            detector_model_signature=(
                str(payload["detector_model_signature"])
                if payload.get("detector_model_signature")
                else None
            ),
            classifier_model_signature=(
                str(payload["classifier_model_signature"])
                if payload.get("classifier_model_signature")
                else None
            ),
            reason=(str(payload["reason"]) if payload.get("reason") else None),
        )

    @classmethod
    def _deserialize_event(cls, payload_json: str, image_blob: bytes) -> EdgeEvent:
        payload = json.loads(payload_json)

        context_payload = payload.get("context", {})
        context = CaptureContext(
            device_id=str(context_payload.get("device_id", "unknown_device")),
            trigger_type=cls._parse_trigger_type(
                context_payload.get("trigger_type")
            ),
            sensor_snapshot=dict(context_payload.get("sensor_snapshot", {})),
            captured_at_ms=int(context_payload.get("captured_at_ms", int(time.time() * 1000))),
        )

        image_payload = payload.get("image", {})
        image = ImagePayload(
            image_id=str(image_payload.get("image_id", "unknown_image")),
            bytes_data=bytes(image_blob),
            format=str(image_payload.get("format", "jpg")),
            width=(
                int(image_payload["width"])
                if image_payload.get("width") is not None
                else None
            ),
            height=(
                int(image_payload["height"])
                if image_payload.get("height") is not None
                else None
            ),
            checksum_sha256=(
                str(image_payload["checksum_sha256"])
                if image_payload.get("checksum_sha256")
                else None
            ),
        )

        local_inference_payload = payload.get("local_inference")
        local_inference = cls._to_local_inference(
            local_inference_payload if isinstance(local_inference_payload, dict) else None
        )

        return EdgeEvent(
            event_id=str(payload.get("event_id", "")),
            trace_id=str(payload.get("trace_id", "")),
            context=context,
            image=image,
            local_inference=local_inference,
            requires_server_assist=bool(payload.get("requires_server_assist", False)),
            metadata=dict(payload.get("metadata", {})),
        )

    def put(self, event: EdgeEvent) -> str:
        record_id = event.event_id
        payload_json = self._serialize_event_payload(event)
        now_ms = int(time.time() * 1000)

        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO edge_spool_events (
                    record_id,
                    event_id,
                    trace_id,
                    payload_json,
                    image_blob,
                    created_at_ms,
                    retry_count,
                    last_retry_reason,
                    last_retry_ms
                ) VALUES (?, ?, ?, ?, ?, ?, 0, NULL, NULL)
                ON CONFLICT(record_id) DO UPDATE SET
                    payload_json = excluded.payload_json,
                    image_blob = excluded.image_blob,
                    trace_id = excluded.trace_id,
                    event_id = excluded.event_id
                """,
                (
                    record_id,
                    event.event_id,
                    event.trace_id,
                    payload_json,
                    event.image.bytes_data,
                    now_ms,
                ),
            )
            conn.commit()

        return record_id

    def peek_batch(self, limit: int) -> Iterable[tuple[str, EdgeEvent]]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT record_id, payload_json, image_blob
                FROM edge_spool_events
                ORDER BY created_at_ms ASC
                LIMIT ?
                """,
                (max(1, limit),),
            ).fetchall()

        for row in rows:
            payload_json = str(row["payload_json"])
            image_blob = bytes(row["image_blob"])
            yield str(row["record_id"]), self._deserialize_event(payload_json, image_blob)

    def ack(self, record_id: str) -> None:
        with self._connect() as conn:
            conn.execute(
                "DELETE FROM edge_spool_events WHERE record_id = ?",
                (record_id,),
            )
            conn.commit()

    def mark_retry(self, record_id: str, reason: str) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                UPDATE edge_spool_events
                SET retry_count = retry_count + 1,
                    last_retry_reason = ?,
                    last_retry_ms = ?
                WHERE record_id = ?
                """,
                (reason, int(time.time() * 1000), record_id),
            )
            conn.commit()
