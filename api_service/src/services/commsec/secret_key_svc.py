from __future__ import annotations

from time import time

from src.models.auth.bootstrap import PublicKeyLookupResult
from src.models.commsec.commsec import (
    LocalPrivateKeyRef,
    ServiceKeyOwner,
    ServicePublicKeyRecord,
)
from src.repo.mysql_client import MySQLClient


class SecretKeyService:
    """密钥服务：本地私钥引用 + 全局公钥目录查询。"""

    def __init__(
        self,
        local_public_key: ServicePublicKeyRecord,
        local_private_key: LocalPrivateKeyRef,
        catalog: list[ServicePublicKeyRecord] | None = None,
        mysql_client: MySQLClient | None = None,
    ):
        self._local_public_key = local_public_key
        self._local_private_key = local_private_key
        self._mysql_client = mysql_client
        self._catalog_by_key_id: dict[str, ServicePublicKeyRecord] = {
            local_public_key.key_id: local_public_key,
        }
        for item in catalog or []:
            self._catalog_by_key_id[item.key_id] = item

    async def get_public_key(self) -> ServicePublicKeyRecord:
        return self._local_public_key

    async def get_private_key_ref(self) -> LocalPrivateKeyRef:
        return self._local_private_key

    async def get_public_key_by_key_id(self, key_id: str) -> PublicKeyLookupResult:
        key = self._catalog_by_key_id.get(key_id)
        if key is None:
            key = await self._load_public_key_by_id(key_id)
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

    async def get_public_keys_by_owner(
        self, owner: ServiceKeyOwner
    ) -> list[ServicePublicKeyRecord]:
        out: list[ServicePublicKeyRecord] = []
        for key in self._catalog_by_key_id.values():
            if owner.owner_type and owner.owner_type != key.owner.owner_type:
                continue
            if owner.service_id and owner.service_id != key.owner.service_id:
                continue
            if owner.service_name and owner.service_name != key.owner.service_name:
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

    async def _load_public_key_by_id(self, key_id: str) -> ServicePublicKeyRecord | None:
        if self._mysql_client is None:
            return None
        async with self._mysql_client.cursor() as cur:
            await cur.execute(
                """
                SELECT key_id, owner_type, service_id, service_name, instance_id, instance_name,
                       key_exchange_algorithm, signature_algorithm, public_key_pem, fingerprint,
                       status, created_at, activated_at, expires_at, revoked_at
                FROM auth_service_public_keys
                WHERE key_id = %s
                LIMIT 1
                """,
                (key_id,),
            )
            row = await cur.fetchone()
        return self._row_to_record(row) if row else None

    async def _load_public_keys_by_owner(self, owner: ServiceKeyOwner) -> list[ServicePublicKeyRecord]:
        if self._mysql_client is None:
            return []

        query = """
            SELECT key_id, owner_type, service_id, service_name, instance_id, instance_name,
                   key_exchange_algorithm, signature_algorithm, public_key_pem, fingerprint,
                   status, created_at, activated_at, expires_at, revoked_at
            FROM auth_service_public_keys
            WHERE 1 = 1
        """
        params: list[str] = []
        if owner.owner_type:
            query += " AND owner_type = %s"
            params.append(owner.owner_type)
        if owner.service_id:
            query += " AND service_id = %s"
            params.append(owner.service_id)
        if owner.service_name:
            query += " AND service_name = %s"
            params.append(owner.service_name)
        if owner.instance_id:
            query += " AND instance_id = %s"
            params.append(owner.instance_id)
        if owner.instance_name:
            query += " AND instance_name = %s"
            params.append(owner.instance_name)

        async with self._mysql_client.cursor() as cur:
            await cur.execute(query, tuple(params))
            rows = await cur.fetchall()

        return [record for row in rows if (record := self._row_to_record(row)) is not None]

    def _row_to_record(self, row: dict | None) -> ServicePublicKeyRecord | None:
        if not row:
            return None
        created_at = row["created_at"].timestamp() if row.get("created_at") else 0.0
        activated_at = row["activated_at"].timestamp() if row.get("activated_at") else 0.0
        expires_at = row["expires_at"].timestamp() if row.get("expires_at") else 0.0
        revoked_at = row["revoked_at"].timestamp() if row.get("revoked_at") else 0.0

        return ServicePublicKeyRecord(
            key_id=str(row["key_id"]),
            owner=ServiceKeyOwner(
                owner_type=str(row["owner_type"]),
                service_id=str(row["service_id"]),
                service_name=str(row["service_name"]),
                instance_id=str(row["instance_id"]),
                instance_name=str(row["instance_name"]),
            ),
            key_exchange_algorithm=str(row["key_exchange_algorithm"]),
            signature_algorithm=str(row["signature_algorithm"]),
            public_key_pem=str(row["public_key_pem"]),
            fingerprint=str(row["fingerprint"]),
            status=str(row["status"]),
            created_at=created_at,
            activated_at=activated_at,
            expires_at=expires_at,
            revoked_at=revoked_at,
        )
