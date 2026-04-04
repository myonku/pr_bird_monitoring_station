from time import time
from typing import Any, cast

from src.models.auth.bootstrap import PublicKeyLookupResult
from src.models.commsec.commsec import (
    LocalPrivateKeyRef,
    ServiceKeyOwner,
    ServicePublicKeyRecord,
)
from src.repo.mysql_client import MySQLClient
from src.repo.mysql_dao import ServicePublicKeysDAO


class SecretKeyService:
    """密钥服务：本地私钥引用 + 全局公钥目录查询。"""

    def __init__(
        self,
        local_public_key: ServicePublicKeyRecord,
        local_private_key: LocalPrivateKeyRef,
        catalog: list[ServicePublicKeyRecord] | None = None,
        mysql_client: MySQLClient | None = None,
    ):
        self._local_public_key = self._normalize_record(local_public_key)
        self._local_private_key = local_private_key
        self._mysql_client = mysql_client
        self._public_keys_dao = (
            ServicePublicKeysDAO(mysql_client) if mysql_client else None
        )
        self._catalog_by_key_id: dict[str, ServicePublicKeyRecord] = {
            self._local_public_key.key_id: self._local_public_key,
        }
        for item in catalog or []:
            normalized = self._normalize_record(item)
            self._catalog_by_key_id[normalized.key_id] = normalized

    # TODO: 后续根据实际需求，更新函数内部实现，支持从安全存储加载或定期刷新本地公钥信息。
    async def get_public_key(self) -> ServicePublicKeyRecord:
        return self._local_public_key

    # TODO: 后续根据实际需求，更新函数内部实现，支持从安全存储加载或定期刷新本地私钥引用信息。
    async def get_private_key_ref(self) -> LocalPrivateKeyRef:
        return self._local_private_key

    async def get_public_key_by_key_id(self, key_id: str) -> PublicKeyLookupResult:
        normalized_key_id = key_id.strip()
        if not normalized_key_id:
            return PublicKeyLookupResult(
                found=False,
                key=None,
                failure_reason="key id is required",
                checked_at=time(),
            )

        key = self._catalog_by_key_id.get(normalized_key_id)
        if key is None:
            key = await self._load_public_key_by_id(normalized_key_id)
            if key is not None:
                self._catalog_by_key_id[key.key_id] = key
        if key is None:
            return PublicKeyLookupResult(
                found=False,
                key=None,
                failure_reason="key id not found",
                checked_at=time(),
            )
        return PublicKeyLookupResult(
            found=True,
            key=key,
            failure_reason="",
            checked_at=time(),
        )

    async def get_public_key_by_entity_id(
        self, entity_id: str
    ) -> PublicKeyLookupResult:
        normalized_entity_id = entity_id.strip()
        if not normalized_entity_id:
            return PublicKeyLookupResult(
                found=False,
                key=None,
                failure_reason="entity id is required",
                checked_at=time(),
            )

        key = self._pick_catalog_key_by_entity_id(normalized_entity_id)
        if key is None:
            key = await self._load_public_key_by_entity_id(normalized_entity_id)
            if key is not None:
                self._catalog_by_key_id[key.key_id] = key

        if key is None:
            return PublicKeyLookupResult(
                found=False,
                key=None,
                failure_reason="entity id not found",
                checked_at=time(),
            )

        return PublicKeyLookupResult(
            found=True,
            key=key,
            failure_reason="",
            checked_at=time(),
        )

    async def get_public_keys_by_owner(
        self, owner: ServiceKeyOwner
    ) -> list[ServicePublicKeyRecord]:
        owner = owner.normalized()
        out: list[ServicePublicKeyRecord] = []
        for key in self._catalog_by_key_id.values():
            if owner.owner_type and owner.owner_type != key.owner.owner_type:
                continue
            if owner.entity_type and owner.entity_type != key.owner.entity_type:
                continue
            if (
                owner.effective_entity_id
                and owner.effective_entity_id != key.owner.effective_entity_id
            ):
                continue
            if (
                owner.effective_entity_name
                and owner.effective_entity_name != key.owner.effective_entity_name
            ):
                continue
            if owner.instance_id and owner.instance_id != key.owner.instance_id:
                continue
            if owner.instance_name and owner.instance_name != key.owner.instance_name:
                continue
            out.append(key)
        if out:
            return out

        db_items = await self._load_public_keys_by_owner(owner)
        for item in db_items:
            self._catalog_by_key_id[item.key_id] = item
        return db_items

    async def _load_public_key_by_id(
        self, key_id: str
    ) -> ServicePublicKeyRecord | None:
        if self._public_keys_dao is None:
            return None
        row = await self._public_keys_dao.find_by_id(key_id)
        return self._row_to_record(row) if row else None

    async def _load_public_key_by_entity_id(
        self, entity_id: str
    ) -> ServicePublicKeyRecord | None:
        if self._public_keys_dao is None:
            return None

        rows = await self._public_keys_dao.find_many(
            filters={"entity_id": entity_id},
            order_by=["-activated_at", "-expires_at"],
            limit=8,
        )
        records = [
            record for row in rows if (record := self._row_to_record(row)) is not None
        ]
        if not records:
            return None

        preferred = records[0]
        for item in records[1:]:
            if self._should_prefer_key(item, preferred):
                preferred = item
        return preferred

    async def _load_public_keys_by_owner(
        self, owner: ServiceKeyOwner
    ) -> list[ServicePublicKeyRecord]:
        if self._public_keys_dao is None:
            return []

        filters: dict[str, str] = {}
        if owner.owner_type:
            filters["owner_type"] = owner.owner_type
        if owner.entity_type:
            filters["entity_type"] = owner.entity_type
        if owner.effective_entity_id:
            filters["entity_id"] = owner.effective_entity_id
        if owner.effective_entity_name:
            filters["entity_name"] = owner.effective_entity_name
        if owner.instance_id:
            filters["instance_id"] = owner.instance_id
        if owner.instance_name:
            filters["instance_name"] = owner.instance_name

        rows = await self._public_keys_dao.find_many(filters=filters or None)

        return [
            record for row in rows if (record := self._row_to_record(row)) is not None
        ]

    def _row_to_record(self, row: dict | None) -> ServicePublicKeyRecord | None:
        if not row:
            return None
        created_at = row["created_at"].timestamp() if row.get("created_at") else 0.0
        activated_at = (
            row["activated_at"].timestamp() if row.get("activated_at") else 0.0
        )
        expires_at = row["expires_at"].timestamp() if row.get("expires_at") else 0.0
        revoked_at = row["revoked_at"].timestamp() if row.get("revoked_at") else 0.0

        entity_type = str(row.get("entity_type") or "")
        entity_id = str(row.get("entity_id") or "")
        entity_name = str(row.get("entity_name") or "")

        return ServicePublicKeyRecord(
            key_id=str(row["key_id"]),
            owner=ServiceKeyOwner(
                owner_type=cast(Any, str(row["owner_type"])),
                entity_type=entity_type,
                entity_id=entity_id,
                entity_name=entity_name,
                service_id=entity_id,
                service_name=entity_name,
                instance_id=str(row.get("instance_id") or ""),
                instance_name=str(row.get("instance_name") or ""),
            ).normalized(),
            key_exchange_algorithm=cast(Any, str(row["key_exchange_algorithm"])),
            signature_algorithm=cast(Any, str(row["signature_algorithm"])),
            public_key_pem=str(row["public_key_pem"]),
            fingerprint=str(row["fingerprint"]),
            status=cast(Any, str(row["status"])),
            created_at=created_at,
            activated_at=activated_at,
            expires_at=expires_at,
            revoked_at=revoked_at,
        )

    def _normalize_record(self, item: ServicePublicKeyRecord) -> ServicePublicKeyRecord:
        return ServicePublicKeyRecord(
            key_id=item.key_id,
            owner=item.owner.normalized(),
            key_exchange_algorithm=item.key_exchange_algorithm,
            signature_algorithm=item.signature_algorithm,
            public_key_pem=item.public_key_pem,
            fingerprint=item.fingerprint,
            status=item.status,
            created_at=item.created_at,
            activated_at=item.activated_at,
            expires_at=item.expires_at,
            revoked_at=item.revoked_at,
        )

    def _pick_catalog_key_by_entity_id(
        self, entity_id: str
    ) -> ServicePublicKeyRecord | None:
        preferred: ServicePublicKeyRecord | None = None
        for key in self._catalog_by_key_id.values():
            if key.owner.effective_entity_id != entity_id:
                continue
            if preferred is None or self._should_prefer_key(key, preferred):
                preferred = key
        return preferred

    @staticmethod
    def _should_prefer_key(
        candidate: ServicePublicKeyRecord,
        current: ServicePublicKeyRecord,
    ) -> bool:
        if candidate.status == "active" and current.status != "active":
            return True
        if candidate.status != "active" and current.status == "active":
            return False
        if candidate.activated_at > current.activated_at:
            return True
        if candidate.expires_at > current.expires_at:
            return True
        return False
