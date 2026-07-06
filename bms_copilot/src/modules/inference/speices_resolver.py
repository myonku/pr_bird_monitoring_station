from __future__ import annotations

import json
from typing import Any
from uuid import UUID

from src.models.business.entities import SpeciesProfile
from src.repo.mysql_client import MySQLClient
from src.repo.mysql_dao import EntitySpeciesProfilesDAO


class SpeciesResolver:
    """基于 MySQL 的物种信息查询器。

    通过推理产出的 label 名称查找对应的 SpeciesProfile。
    查询策略：依次尝试 label_name → scientific_name → display_name 三种匹配。
    """

    def __init__(self, mysql_client: MySQLClient) -> None:
        if mysql_client is None:
            raise ValueError("mysql_client is required")
        self._dao = EntitySpeciesProfilesDAO(mysql_client)

    async def resolve_by_label(self, label: str) -> SpeciesProfile | None:
        """按 label 名称查询物种信息，三种匹配策略依次回退。"""
        normalized = (label or "").strip()
        if not normalized:
            return None

        row = await self._dao.find_one(filters={"label_name": normalized})
        if row:
            profile = self._row_to_profile(row)
            if profile is not None:
                return profile

        row = await self._dao.find_one(filters={"scientific_name": normalized})
        if row:
            profile = self._row_to_profile(row)
            if profile is not None:
                return profile

        row = await self._dao.find_one(filters={"species_name": normalized})
        if row:
            profile = self._row_to_profile(row)
            if profile is not None:
                return profile

        return None

    async def resolve_by_id(self, species_entity_id: UUID) -> SpeciesProfile | None:
        """按 species_entity_id 精确查询。"""
        if species_entity_id.int == 0:
            return None
        row = await self._dao.find_by_id(str(species_entity_id))
        return self._row_to_profile(row)

    @staticmethod
    def _row_to_profile(row: dict[str, Any] | None) -> SpeciesProfile | None:
        if not row:
            return None

        try:
            species_entity_id = UUID(str(row.get("species_entity_id") or "").strip())
        except (ValueError, TypeError):
            return None

        scientific_name = str(row.get("scientific_name") or "").strip()
        if not scientific_name:
            return None

        label_name = str(row.get("label_name") or "").strip()
        display_name = str(row.get("species_name") or "").strip()
        metadata = _decode_json_object(row.get("metadata"))

        return SpeciesProfile(
            species_entity_id=species_entity_id,
            scientific_name=scientific_name,
            label_name=label_name,
            display_name=display_name,
            intro=str(metadata.get("intro") or ""),
            habitat=str(metadata.get("habitat") or ""),
            protection_level=str(metadata.get("protection_level") or ""),
            alias_names=_decode_json_array(row.get("alias_names")),
            metadata={str(k): str(v) for k, v in metadata.items()},
        )

def _decode_json_array(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item) for item in value]
    if isinstance(value, (bytes, bytearray)):
        value = value.decode("utf-8", errors="ignore")
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return []
        try:
            parsed = json.loads(text)
            return [str(item) for item in parsed] if isinstance(parsed, list) else []
        except json.JSONDecodeError:
            return []
    return []


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
