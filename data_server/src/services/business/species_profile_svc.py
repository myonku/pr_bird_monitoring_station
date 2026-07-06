from __future__ import annotations

import json
from datetime import datetime
from typing import Any
from uuid import UUID

from src.iface.business.species_profile_svc import ISpeciesProfileManager
from src.models.business.entities import SpeciesProfile
from src.repo.mysql_client import MySQLClient
from src.repo.mysql_dao import EntitySpeciesProfilesDAO


class SpeciesProfileManager(ISpeciesProfileManager):
    """基于 MySQL 的鸟类信息管理器。"""

    def __init__(
        self,
        *,
        mysql_client: MySQLClient | None = None,
    ) -> None:
        if mysql_client is None:
            raise ValueError("species profile manager dependencies are required")
        self._species_dao = EntitySpeciesProfilesDAO(mysql_client)

    async def get_by_id(self, species_entity_id: UUID) -> SpeciesProfile | None:
        if species_entity_id.int == 0:
            raise ValueError("species_entity_id is required")
        row = await self._species_dao.find_by_id(str(species_entity_id))
        return self._row_to_profile(row)

    async def get_by_scientific_name(self, scientific_name: str) -> SpeciesProfile | None:
        normalized = (scientific_name or "").strip()
        if not normalized:
            raise ValueError("scientific_name is required")
        row = await self._species_dao.find_one(
            filters={"scientific_name": normalized},
        )
        return self._row_to_profile(row)

    async def get_by_label_name(self, label_name: str) -> SpeciesProfile | None:
        normalized = (label_name or "").strip()
        if not normalized:
            raise ValueError("label_name is required")
        row = await self._species_dao.find_one(
            filters={"label_name": normalized},
        )
        return self._row_to_profile(row)

    async def get_by_display_name(self, display_name: str) -> SpeciesProfile | None:
        normalized = (display_name or "").strip()
        if not normalized:
            raise ValueError("display_name is required")
        row = await self._species_dao.find_one(
            filters={"species_name": normalized},
        )
        return self._row_to_profile(row)

    async def list_all(self) -> list[SpeciesProfile]:
        rows = await self._species_dao.find_many(order_by=["scientific_name"])
        items = [
            profile for row in rows if (profile := self._row_to_profile(row)) is not None
        ]
        items.sort(key=lambda item: (item.scientific_name, str(item.species_entity_id)))
        return items

    async def create(self, profile: SpeciesProfile) -> UUID:
        if profile is None:
            raise ValueError("species profile is required")

        now = datetime.utcnow()
        data = self._profile_to_row(profile)
        data["created_at"] = now
        data["updated_at"] = now

        inserted_id = await self._species_dao.insert_one(data)
        if inserted_id is None:
            return profile.species_entity_id
        return UUID(str(inserted_id))

    async def update(self, profile: SpeciesProfile) -> bool:
        if profile is None:
            raise ValueError("species profile is required")

        update_data = self._profile_to_row(profile)
        update_data["updated_at"] = datetime.utcnow()
        return await self._species_dao.update_by_id(
            str(profile.species_entity_id),
            update_data,
        )

    async def delete(self, species_entity_id: UUID) -> bool:
        if species_entity_id.int == 0:
            raise ValueError("species_entity_id is required")
        return await self._species_dao.delete_by_id(str(species_entity_id))

    @staticmethod
    def _row_to_profile(row: dict[str, Any] | None) -> SpeciesProfile | None:
        if not row:
            return None

        try:
            species_entity_id = UUID(str(row.get("species_entity_id") or "").strip())
        except ValueError:
            return None

        scientific_name = str(row.get("scientific_name") or "").strip()
        if not scientific_name:
            return None

        label_name = str(row.get("label_name") or "").strip()
        display_name = str(row.get("species_name") or "").strip()
        alias_names = SpeciesProfileManager._decode_json_array(row.get("alias_names"))
        metadata_any = SpeciesProfileManager._decode_json_object(row.get("metadata"))
        metadata = {str(k): str(v) for k, v in metadata_any.items()}

        return SpeciesProfile(
            species_entity_id=species_entity_id,
            scientific_name=scientific_name,
            label_name=label_name,
            display_name=display_name,
            intro=str(metadata.get("intro") or ""),
            habitat=str(metadata.get("habitat") or ""),
            protection_level=str(metadata.get("protection_level") or ""),
            alias_names=[str(item) for item in alias_names],
            metadata=metadata,
        )

    @staticmethod
    def _profile_to_row(profile: SpeciesProfile) -> dict[str, Any]:
        metadata = dict(profile.metadata or {})
        if profile.intro:
            metadata.setdefault("intro", profile.intro)
        if profile.habitat:
            metadata.setdefault("habitat", profile.habitat)
        if profile.protection_level:
            metadata.setdefault("protection_level", profile.protection_level)

        return {
            "species_entity_id": str(profile.species_entity_id),
            "species_name": profile.display_name.strip() or profile.scientific_name.strip(),
            "scientific_name": profile.scientific_name.strip(),
            "label_name": (
                profile.label_name.strip()
                or profile.display_name.strip()
                or profile.scientific_name.strip()
            ),
            "alias_names": json.dumps(list(profile.alias_names or []), ensure_ascii=True),
            "metadata": json.dumps(metadata, ensure_ascii=True),
        }

    @staticmethod
    def _decode_json_array(value: Any) -> list[Any]:
        if value is None:
            return []
        if isinstance(value, list):
            return value
        if isinstance(value, (bytes, bytearray)):
            value = value.decode("utf-8", errors="ignore")
        if isinstance(value, str):
            text = value.strip()
            if not text:
                return []
            try:
                parsed = json.loads(text)
                return parsed if isinstance(parsed, list) else []
            except json.JSONDecodeError:
                return []
        return []

    @staticmethod
    def _decode_json_object(value: Any) -> dict[str, Any]:
        if value is None:
            return {}
        if isinstance(value, dict):
            return value
        if isinstance(value, (bytes, bytearray)):
            value = value.decode("utf-8", errors="ignore")
        if isinstance(value, str):
            text = value.strip()
            if not text:
                return {}
            try:
                parsed = json.loads(text)
                return parsed if isinstance(parsed, dict) else {}
            except json.JSONDecodeError:
                return {}
        return {}