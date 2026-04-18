from __future__ import annotations

from datetime import date, datetime, time, timezone
from uuid import UUID

from src.iface.business.envelope_svc import IEnvelopeManager
from src.models.business.data import EdgeEventEnvelope


class EnvelopeManager(IEnvelopeManager):
    """边缘事件信封的 Beanie CRUD 管理器。"""

    def __init__(self, document_model: type[EdgeEventEnvelope] = EdgeEventEnvelope) -> None:
        self._document_model = document_model

    async def get_by_id(self, event_id: UUID) -> EdgeEventEnvelope | None:
        if event_id.int == 0:
            raise ValueError("event_id is required")
        return await self._document_model.get(event_id)

    async def list_all(self) -> list[EdgeEventEnvelope]:
        items = await self._document_model.find_all().to_list()
        items.sort(key=lambda item: str(item.id))
        return items

    async def create(self, envelope: EdgeEventEnvelope) -> EdgeEventEnvelope:
        if envelope is None:
            raise ValueError("edge event envelope is required")
        return await envelope.insert()

    async def update(self, envelope: EdgeEventEnvelope) -> EdgeEventEnvelope | None:
        if envelope is None:
            raise ValueError("edge event envelope is required")
        if envelope.id.int == 0:
            raise ValueError("event_id is required")
        existing = await self._document_model.get(envelope.id)
        if existing is None:
            return None
        await envelope.save()
        return envelope

    async def delete(self, event_id: UUID) -> bool:
        if event_id.int == 0:
            raise ValueError("event_id is required")
        existing = await self._document_model.get(event_id)
        if existing is None:
            return False
        await existing.delete()
        return True

    async def count_today_upload_records(self) -> int:
        today_start_ms = self._day_start_ms(datetime.now(timezone.utc).date())
        return await self._document_model.find({"received_at_ms": {"$gte": today_start_ms}}).count()

    async def get_today_top_upload_site(self) -> dict[str, object] | None:
        today_start_ms = self._day_start_ms(datetime.now(timezone.utc).date())
        items = await self._document_model.find({"received_at_ms": {"$gte": today_start_ms}}).to_list()
        if not items:
            return None

        counts: dict[UUID, tuple[UUID, str, int]] = {}
        for item in items:
            current = counts.get(item.device_entity_id)
            if current is None:
                counts[item.device_entity_id] = (item.device_entity_id, item.device_name, 1)
            else:
                counts[item.device_entity_id] = (current[0], current[1], current[2] + 1)

        top = max(
            counts.values(),
            key=lambda entry: (entry[2], str(entry[0])),
        )
        return {
            "device_entity_id": top[0],
            "device_name": top[1],
            "upload_count": top[2],
        }

    async def get_latest_upload_summary(self) -> dict[str, object] | None:
        items = await self._document_model.find_all().to_list()
        if not items:
            return None

        latest = max(
            items,
            key=lambda item: (item.received_at_ms, str(item.id)),
        )
        return {
            "received_at_ms": latest.received_at_ms,
            "device_entity_id": latest.device_entity_id,
            "device_name": latest.device_name,
        }

    @staticmethod
    def _day_start_ms(day: date) -> int:
        day_start = datetime.combine(day, time.min, tzinfo=timezone.utc)
        return int(day_start.timestamp() * 1000)