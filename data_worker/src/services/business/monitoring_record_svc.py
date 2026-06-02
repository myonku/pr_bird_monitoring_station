from __future__ import annotations

from datetime import date, datetime, time, timedelta, timezone
from uuid import UUID

from src.iface.business.monitoring_record_svc import IMonitoringRecordManager
from src.models.business.data import MonitoringRecord


MIN_VISIBLE_CONFIDENCE = 0.8


class MonitoringRecordManager(IMonitoringRecordManager):
    """监测记录的 Beanie CRUD 管理器。"""

    def __init__(self, document_model: type[MonitoringRecord] = MonitoringRecord) -> None:
        self._document_model = document_model

    async def get_by_id(self, record_id: UUID) -> MonitoringRecord | None:
        if record_id.int == 0:
            raise ValueError("record_id is required")
        record = await self._document_model.get(record_id)
        if record is None or float(getattr(record, "confidence", 0.0) or 0.0) <= MIN_VISIBLE_CONFIDENCE:
            return None
        return record

    async def list_recent_week(
        self,
        device_entity_id: UUID | None = None,
    ) -> list[MonitoringRecord]:
        today = datetime.now(timezone.utc).date()
        start_day = today - timedelta(days=6)
        return await self.list_by_day_range(
            start_day=start_day,
            end_day=today,
            device_entity_id=device_entity_id,
        )

    async def list_by_day_range(
        self,
        start_day: date,
        end_day: date,
        device_entity_id: UUID | None = None,
    ) -> list[MonitoringRecord]:
        if start_day is None or end_day is None:
            raise ValueError("start_day and end_day are required")
        if end_day < start_day:
            raise ValueError("end_day must be greater than or equal to start_day")

        start_ms = self._day_start_ms(start_day)
        end_ms = self._day_start_ms(end_day + timedelta(days=1))

        query: dict[str, object] = {
            "captured_at_ms": {"$gte": start_ms, "$lt": end_ms},
            "confidence": {"$gt": MIN_VISIBLE_CONFIDENCE},
        }
        if device_entity_id is not None:
            if device_entity_id.int == 0:
                raise ValueError("device_entity_id is required")
            query["device_entity_id"] = device_entity_id

        items = await self._document_model.find(query).to_list()
        items.sort(key=lambda item: (item.captured_at_ms, str(item.id)))
        return items

    async def list_all(self) -> list[MonitoringRecord]:
        items = await self._document_model.find({"confidence": {"$gt": MIN_VISIBLE_CONFIDENCE}}).to_list()
        items.sort(key=lambda item: str(item.id))
        return items

    async def create(self, record: MonitoringRecord) -> MonitoringRecord:
        if record is None:
            raise ValueError("monitoring record is required")
        return await record.insert()

    async def update(self, record: MonitoringRecord) -> MonitoringRecord | None:
        if record is None:
            raise ValueError("monitoring record is required")
        if record.id.int == 0:
            raise ValueError("record_id is required")
        existing = await self._document_model.get(record.id)
        if existing is None:
            return None
        await record.save()
        return record

    async def delete(self, record_id: UUID) -> bool:
        if record_id.int == 0:
            raise ValueError("record_id is required")
        existing = await self._document_model.get(record_id)
        if existing is None:
            return False
        await existing.delete()
        return True

    async def count_today_monitoring_records(self) -> int:
        today_start_ms = self._day_start_ms(datetime.now(timezone.utc).date())
        return await self._document_model.find(
            {
                "captured_at_ms": {"$gte": today_start_ms},
                "confidence": {"$gt": MIN_VISIBLE_CONFIDENCE},
            }
        ).count()

    async def list_latest_three(self) -> list[MonitoringRecord]:
        items = await self._document_model.find(
            {"confidence": {"$gt": MIN_VISIBLE_CONFIDENCE}}
        ).to_list()
        items.sort(key=lambda item: (item.captured_at_ms, str(item.id)), reverse=True)
        return items[:3]

    async def list_recent_week_daily_counts(self) -> list[dict[str, object]]:
        today = datetime.now(timezone.utc).date()
        start_day = today - timedelta(days=6)
        start_ms = self._day_start_ms(start_day)
        end_ms = self._day_start_ms(today + timedelta(days=1))

        items = await self._document_model.find(
            {
                "captured_at_ms": {"$gte": start_ms, "$lt": end_ms},
                "confidence": {"$gt": MIN_VISIBLE_CONFIDENCE},
            }
        ).to_list()

        counts: dict[date, int] = {start_day + timedelta(days=offset): 0 for offset in range(7)}
        for item in items:
            day = datetime.fromtimestamp(item.captured_at_ms / 1000.0, tz=timezone.utc).date()
            if day in counts:
                counts[day] += 1

        return [
            {"day": day.isoformat(), "count": counts[day]}
            for day in sorted(counts.keys())
        ]

    @staticmethod
    def _day_start_ms(day: date) -> int:
        day_start = datetime.combine(day, time.min, tzinfo=timezone.utc)
        return int(day_start.timestamp() * 1000)