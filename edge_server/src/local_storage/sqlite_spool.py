import json
import shutil
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

    _MAX_RETRY_COUNT = 8
    _RETRY_BASE_DELAY_MS = 2_000
    _RETRY_MAX_DELAY_MS = 5 * 60 * 1_000

    _MAX_SPOOL_RECORDS = 10_000
    _SPOOL_LIMIT_FRACTION = 0.12
    _SPOOL_MIN_LIMIT_BYTES = 64 * 1024 * 1024
    _SPOOL_MAX_LIMIT_BYTES = 1 * 1024 * 1024 * 1024
    _RESERVED_FREE_BYTES = 512 * 1024 * 1024
    _CRITICAL_FREE_BYTES = 128 * 1024 * 1024

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
                    next_retry_ms INTEGER NOT NULL DEFAULT 0,
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
            self._ensure_column(
                conn,
                column_name="next_retry_ms",
                column_ddl="INTEGER NOT NULL DEFAULT 0",
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_edge_spool_events_retry
                ON edge_spool_events (next_retry_ms, created_at_ms)
                """
            )
            conn.commit()

    @staticmethod
    def _ensure_column(
        conn,
        *,
        column_name: str,
        column_ddl: str,
    ) -> None:
        rows = conn.execute("PRAGMA table_info(edge_spool_events)").fetchall()
        columns = {str(row["name"]) for row in rows}
        if column_name in columns:
            return
        conn.execute(
            f"ALTER TABLE edge_spool_events ADD COLUMN {column_name} {column_ddl}"
        )

    @staticmethod
    def _estimate_event_bytes(payload_json: str, image_blob: bytes) -> int:
        return len(payload_json.encode("utf-8")) + len(image_blob) + 2048

    def _compute_dynamic_spool_limit_bytes(self) -> int:
        try:
            free_bytes = int(shutil.disk_usage(self._sqlite.db_path.parent).free)
        except OSError:
            return self._SPOOL_MIN_LIMIT_BYTES

        if free_bytes <= self._CRITICAL_FREE_BYTES:
            return 0

        ratio_limit = int(free_bytes * self._SPOOL_LIMIT_FRACTION)
        ratio_limit = min(self._SPOOL_MAX_LIMIT_BYTES, max(0, ratio_limit))
        reserve_budget = max(0, free_bytes - self._RESERVED_FREE_BYTES)

        if reserve_budget <= 0:
            return min(ratio_limit, self._SPOOL_MIN_LIMIT_BYTES)

        if reserve_budget < self._SPOOL_MIN_LIMIT_BYTES:
            return reserve_budget

        return max(
            self._SPOOL_MIN_LIMIT_BYTES,
            min(ratio_limit, reserve_budget),
        )

    @staticmethod
    def _current_payload_bytes(conn) -> int:
        row = conn.execute(
            """
            SELECT COALESCE(SUM(LENGTH(payload_json) + LENGTH(image_blob)), 0) AS used_bytes
            FROM edge_spool_events
            """
        ).fetchone()
        return int(row["used_bytes"] or 0)

    @staticmethod
    def _current_record_count(conn) -> int:
        row = conn.execute("SELECT COUNT(1) AS total FROM edge_spool_events").fetchone()
        return int(row["total"] or 0)

    @staticmethod
    def _evict_oldest(conn) -> bool:
        row = conn.execute(
            """
            SELECT record_id
            FROM edge_spool_events
            ORDER BY created_at_ms ASC
            LIMIT 1
            """
        ).fetchone()
        if row is None:
            return False

        conn.execute(
            "DELETE FROM edge_spool_events WHERE record_id = ?",
            (str(row["record_id"]),),
        )
        return True

    def _ensure_capacity_for_insert(self, conn, incoming_bytes: int) -> bool:
        limit_bytes = self._compute_dynamic_spool_limit_bytes()
        if limit_bytes <= 0:
            # 磁盘空间过低时放弃新缓存，优先保护系统可用空间。
            return False

        while True:
            current_records = self._current_record_count(conn)
            current_bytes = self._current_payload_bytes(conn)

            exceeds_record_limit = current_records >= self._MAX_SPOOL_RECORDS
            exceeds_byte_limit = (current_bytes + incoming_bytes) > limit_bytes

            if not exceeds_record_limit and not exceeds_byte_limit:
                return True

            evicted = self._evict_oldest(conn)
            if not evicted:
                return False

    @classmethod
    def _compute_retry_delay_ms(cls, retry_count: int) -> int:
        power = max(0, retry_count - 1)
        delay = cls._RETRY_BASE_DELAY_MS * (2**power)
        return int(min(cls._RETRY_MAX_DELAY_MS, delay))

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
        image_blob = event.image.bytes_data
        incoming_bytes = self._estimate_event_bytes(payload_json, image_blob)
        now_ms = int(time.time() * 1000)

        with self._connect() as conn:
            can_store = self._ensure_capacity_for_insert(conn, incoming_bytes)
            if not can_store:
                conn.commit()
                return record_id

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
                    next_retry_ms,
                    last_retry_reason,
                    last_retry_ms
                ) VALUES (?, ?, ?, ?, ?, ?, 0, 0, NULL, NULL)
                ON CONFLICT(record_id) DO UPDATE SET
                    payload_json = excluded.payload_json,
                    image_blob = excluded.image_blob,
                    trace_id = excluded.trace_id,
                    event_id = excluded.event_id,
                    next_retry_ms = 0
                """,
                (
                    record_id,
                    event.event_id,
                    event.trace_id,
                    payload_json,
                    image_blob,
                    now_ms,
                ),
            )
            conn.commit()

        return record_id

    def peek_batch(self, limit: int) -> Iterable[tuple[str, EdgeEvent]]:
        now_ms = int(time.time() * 1000)
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT record_id, payload_json, image_blob
                FROM edge_spool_events
                WHERE COALESCE(next_retry_ms, 0) <= ?
                ORDER BY next_retry_ms ASC, created_at_ms ASC
                LIMIT ?
                """,
                (now_ms, max(1, limit)),
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
            row = conn.execute(
                "SELECT retry_count FROM edge_spool_events WHERE record_id = ?",
                (record_id,),
            ).fetchone()
            if row is None:
                return

            retry_count = int(row["retry_count"] or 0) + 1
            if retry_count >= self._MAX_RETRY_COUNT:
                conn.execute(
                    "DELETE FROM edge_spool_events WHERE record_id = ?",
                    (record_id,),
                )
                conn.commit()
                return

            now_ms = int(time.time() * 1000)
            next_retry_ms = now_ms + self._compute_retry_delay_ms(retry_count)

            conn.execute(
                """
                UPDATE edge_spool_events
                SET retry_count = ?,
                    next_retry_ms = ?,
                    last_retry_reason = ?,
                    last_retry_ms = ?
                WHERE record_id = ?
                """,
                (retry_count, next_retry_ms, reason, now_ms, record_id),
            )
            conn.commit()
