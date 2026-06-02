from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace
from typing import Any
from unittest import IsolatedAsyncioTestCase
from unittest.mock import AsyncMock, Mock
from uuid import uuid4

from src.models.business.client_req_dto import ClientRecordsCursorRequest
from src.models.business.data import MONITORING_CONFIDENCE_MIN, MonitoringRecord
from src.services.business.data_server_svc import DataServerService
from src.services.business.monitoring_record_svc import MonitoringRecordManager


def _current_ms() -> int:
    return int(datetime.now(timezone.utc).timestamp() * 1000)


def _make_record(
    confidence: float,
    *,
    captured_at_ms: int,
    device_id: str,
    suffix: str,
) -> MonitoringRecord:
    return MonitoringRecord(
        id=uuid4(),
        device_entity_id=uuid4(),
        device_name=f"station-{suffix}",
        source_event_id=uuid4(),
        species_entity_id=uuid4(),
        captured_at_ms=captured_at_ms,
        species_name=f"species-{suffix}",
        scientific_name=f"scientific-{suffix}",
        confidence=confidence,
        processing_source="edge",
        model_version="v1",
        summary_text=f"summary-{suffix}",
        species_intro=f"intro-{suffix}",
        record_status="published",
        metadata={"device_id": device_id},
    )


def _build_service(
    records: list[MonitoringRecord],
    *,
    devices: list[Any] | None = None,
    envelopes: list[Any] | None = None,
) -> DataServerService:
    record_manager = Mock()
    record_manager.list_all = AsyncMock(return_value=list(records))
    record_manager.list_latest_three = AsyncMock(return_value=list(records))
    record_manager.count_today_monitoring_records = AsyncMock(
        return_value=sum(1 for record in records if record.confidence >= MONITORING_CONFIDENCE_MIN)
    )

    device_entity_manager = Mock()
    device_entity_manager.list_all = AsyncMock(return_value=list(devices or []))

    envelope_manager = Mock()
    envelope_manager.list_all = AsyncMock(return_value=list(envelopes or []))

    empty_manager = Mock()

    return DataServerService(
        user_profile_manager=empty_manager,
        user_entity_manager=empty_manager,
        device_entity_manager=device_entity_manager,
        species_profile_manager=empty_manager,
        record_manager=record_manager,
        envelope_manager=envelope_manager,
    )


class MonitoringConfidenceFilterTests(IsolatedAsyncioTestCase):
    async def test_cursor_query_clamps_confidence_min_to_eighty_percent(self) -> None:
        now_ms = _current_ms()
        records = [
            _make_record(0.75, captured_at_ms=now_ms - 3000, device_id="A", suffix="low"),
            _make_record(0.80, captured_at_ms=now_ms - 2000, device_id="B", suffix="edge"),
            _make_record(0.95, captured_at_ms=now_ms - 1000, device_id="C", suffix="high"),
        ]
        service = _build_service(records)

        response = await service.list_records_by_cursor(
            ClientRecordsCursorRequest(confidence_min=0.5, limit=10)
        )

        self.assertEqual([0.95, 0.80], [item.confidence for item in response.items])
        self.assertTrue(all(item.confidence >= MONITORING_CONFIDENCE_MIN for item in response.items))

    async def test_recent_records_and_dashboard_snapshot_hide_low_confidence_records(self) -> None:
        now_ms = _current_ms()
        records = [
            _make_record(0.75, captured_at_ms=now_ms - 3000, device_id="A", suffix="low"),
            _make_record(0.80, captured_at_ms=now_ms - 2000, device_id="B", suffix="edge"),
            _make_record(0.95, captured_at_ms=now_ms - 1000, device_id="C", suffix="high"),
        ]
        devices = [SimpleNamespace(device_entity_id=uuid4()), SimpleNamespace(device_entity_id=uuid4())]
        service = _build_service(records, devices=devices, envelopes=[])

        recent_records = await service.list_recent_records(limit=5)
        snapshot = await service.get_dashboard_snapshot()

        self.assertEqual([0.95, 0.80], [item.confidence for item in recent_records])
        self.assertEqual(2, snapshot.today_recognition_count)
        self.assertEqual(2, snapshot.active_station_count)
        self.assertEqual([0.95, 0.80], [item.confidence for item in snapshot.recent_records])
        self.assertTrue(all(item.confidence >= MONITORING_CONFIDENCE_MIN for item in snapshot.recent_records))


class MonitoringRecordManagerConfidenceTests(IsolatedAsyncioTestCase):
    async def test_manager_queries_apply_confidence_floor(self) -> None:
        class FakeQuery:
            def __init__(self, items: list[MonitoringRecord]) -> None:
                self._items = list(items)

            async def to_list(self) -> list[MonitoringRecord]:
                return list(self._items)

            async def count(self) -> int:
                return len(self._items)

        class FakeDocumentModel:
            def __init__(self) -> None:
                self.queries: list[dict[str, object]] = []

            def find(self, query: dict[str, object]) -> FakeQuery:
                self.queries.append(query)
                return FakeQuery([])

        fake_model = FakeDocumentModel()
        manager = MonitoringRecordManager(document_model=fake_model)  # type: ignore[arg-type]

        await manager.count_today_monitoring_records()
        await manager.list_latest_three()

        self.assertEqual(2, len(fake_model.queries))
        for query in fake_model.queries:
            self.assertIn("confidence", query)
            self.assertEqual(
                MONITORING_CONFIDENCE_MIN,
                query["confidence"]["$gte"], # type: ignore
            )
