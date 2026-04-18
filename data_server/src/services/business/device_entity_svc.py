from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any
from uuid import UUID

from src.iface.business.device_entity_svc import IDeviceEntityManager
from src.models.common.entities import DeviceEntity
from src.repo.mysql_client import MySQLClient
from src.repo.mysql_dao import EntityDevicesDAO


class DeviceEntityManager(IDeviceEntityManager):
    """基于 MySQL 的设备实体管理器。"""

    def __init__(
        self,
        *,
        mysql_client: MySQLClient | None = None,
        device_dao: EntityDevicesDAO | None = None,
    ) -> None:
        if device_dao is None and mysql_client is None:
            raise ValueError("device entity manager dependencies are required")
        if device_dao is not None:
            self._device_dao = device_dao
        else:
            assert mysql_client is not None
            self._device_dao = EntityDevicesDAO(mysql_client)

    async def get_by_id(self, device_entity_id: UUID) -> DeviceEntity | None:
        if device_entity_id.int == 0:
            raise ValueError("device_entity_id is required")
        row = await self._device_dao.find_by_id(str(device_entity_id))
        return self._row_to_device(row)

    async def list_all(self) -> list[DeviceEntity]:
        rows = await self._device_dao.find_many(order_by=["device_name", "device_entity_id"])
        items = [
            device for row in rows if (device := self._row_to_device(row)) is not None
        ]
        items.sort(key=lambda item: (item.device_name, str(item.device_entity_id)))
        return items

    async def create(self, device_entity: DeviceEntity) -> UUID:
        if device_entity is None:
            raise ValueError("device entity is required")

        data = self._device_to_row(device_entity)
        inserted_id = await self._device_dao.insert_one(data)
        if inserted_id is None:
            return device_entity.device_entity_id
        return UUID(str(inserted_id))

    async def update(self, device_entity: DeviceEntity) -> bool:
        if device_entity is None:
            raise ValueError("device entity is required")

        update_data = self._device_to_row(device_entity)
        return await self._device_dao.update_by_id(
            str(device_entity.device_entity_id),
            update_data,
        )

    async def delete(self, device_entity_id: UUID) -> bool:
        if device_entity_id.int == 0:
            raise ValueError("device_entity_id is required")
        return await self._device_dao.delete_by_id(str(device_entity_id))

    @staticmethod
    def _row_to_device(row: dict[str, Any] | None) -> DeviceEntity | None:
        if not row:
            return None

        try:
            device_entity_id = UUID(str(row.get("device_entity_id") or "").strip())
        except ValueError:
            return None

        try:
            active_comm_key_id_raw = str(row.get("active_comm_key_id") or "").strip()
            active_comm_key_id = UUID(active_comm_key_id_raw) if active_comm_key_id_raw else None
        except ValueError:
            active_comm_key_id = None

        return DeviceEntity(
            device_entity_id=device_entity_id,
            device_name=str(row.get("device_name") or ""),
            location_name=str(row.get("location_name") or ""),
            latitude=DeviceEntityManager._to_float(row.get("latitude")),
            longitude=DeviceEntityManager._to_float(row.get("longitude")),
            last_heartbeat_ms=DeviceEntityManager._datetime_to_ms(row.get("last_heartbeat_at")),
            status=str(row.get("status") or "unknown"),
            active_comm_key_id=active_comm_key_id,
            created_at_ms=DeviceEntityManager._datetime_to_ms(row.get("created_at")),
            updated_at_ms=DeviceEntityManager._datetime_to_ms(row.get("updated_at")),
            metadata=DeviceEntityManager._decode_json_object(row.get("metadata")),
        )

    @staticmethod
    def _device_to_row(device_entity: DeviceEntity) -> dict[str, Any]:
        if device_entity.latitude is None or device_entity.longitude is None:
            raise ValueError("device latitude and longitude are required")
        if device_entity.active_comm_key_id is None:
            raise ValueError("active_comm_key_id is required")

        return {
            "device_entity_id": str(device_entity.device_entity_id),
            "device_name": device_entity.device_name.strip(),
            "location_name": device_entity.location_name.strip(),
            "latitude": float(device_entity.latitude),
            "longitude": float(device_entity.longitude),
            "last_heartbeat_at": DeviceEntityManager._ms_to_datetime(device_entity.last_heartbeat_ms),
            "status": device_entity.status,
            "active_comm_key_id": str(device_entity.active_comm_key_id),
            "created_at": DeviceEntityManager._ms_to_datetime(device_entity.created_at_ms),
            "updated_at": DeviceEntityManager._ms_to_datetime(device_entity.updated_at_ms),
            "metadata": json.dumps(device_entity.metadata or {}, ensure_ascii=True),
        }

    @staticmethod
    def _ms_to_datetime(ms: int) -> datetime:
        return datetime.fromtimestamp(max(int(ms), 0) / 1000.0, tz=timezone.utc)

    @staticmethod
    def _datetime_to_ms(value: Any) -> int:
        if value is None:
            return 0
        if not isinstance(value, datetime):
            return 0
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return int(value.timestamp() * 1000)

    @staticmethod
    def _to_float(value: Any) -> float | None:
        if value is None or value == "":
            return None
        try:
            return float(value)
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _decode_json_object(value: Any) -> dict[str, str]:
        if value is None:
            return {}
        if isinstance(value, dict):
            return {str(key): str(item) for key, item in value.items()}
        if isinstance(value, (bytes, bytearray)):
            value = value.decode("utf-8", errors="ignore")
        if isinstance(value, str):
            text = value.strip()
            if not text:
                return {}
            try:
                parsed = json.loads(text)
            except json.JSONDecodeError:
                return {}
            if isinstance(parsed, dict):
                return {str(key): str(item) for key, item in parsed.items()}
        return {}