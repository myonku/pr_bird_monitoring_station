from __future__ import annotations

import base64
import hashlib
from pathlib import Path
from time import time
from typing import cast

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

from src.models.commsec.commsec import (
    CommKeyStatus,
    LocalPrivateKeyRef,
    PublicKeyLookupRequest,
    PublicKeyLookupResult,
    ServiceKeyOwner,
    ServicePublicKeyRecord,
    SignatureAlgorithm,
)
from src.models.sys.config import ProjectConfig, SecretKeyStartupParams
from src.repo.mysql_client import MySQLClient
from src.repo.mysql_dao import ServicePublicKeysDAO


class SecretKeyService:
    """密钥服务：本地私钥引用 + 全局公钥目录查询。"""

    @classmethod
    def from_project_config(
        cls,
        *,
        config: ProjectConfig | None,
        default_entity_id: str = "data_worker",
        catalog: list[ServicePublicKeyRecord] | None = None,
        mysql_client: MySQLClient | None = None,
    ) -> tuple["SecretKeyService", SecretKeyStartupParams]:
        """从主流程注入的配置模型实例构建密钥服务。

        该入口禁止在服务层读取配置文件，仅解析配置实例并委托启动参数构造器。
        """
        if config is None:
            raise ValueError("project config is required")

        startup_params = config.build_secret_key_startup_params(
            default_entity_id=default_entity_id,
        )
        service = cls.from_startup_params(
            params=startup_params,
            catalog=catalog,
            mysql_client=mysql_client,
        )
        return service, startup_params

    @classmethod
    def from_startup_params(
        cls,
        *,
        params: SecretKeyStartupParams,
        catalog: list[ServicePublicKeyRecord] | None = None,
        mysql_client: MySQLClient | None = None,
    ) -> "SecretKeyService":
        """基于启动参数快照构建密钥服务。

        这里统一解析本地 key_id 的来源：active_key_id 优先，其次是 instance_id，再其次是 entity_id。
        """
        resolved_key_id = (
            params.active_key_id.strip()
            or params.instance_id.strip()
            or params.entity_id.strip()
        )
        if not resolved_key_id:
            raise ValueError("bootstrap key id requires active_key_id, instance_id, or entity_id")

        owner = ServiceKeyOwner(
            entity_type=params.entity_type,
            entity_id=params.entity_id,
            entity_name=params.entity_name,
            instance_id=params.instance_id,
            instance_name=params.instance_name,
        ).normalized()

        return cls.from_secret_dir(
            owner=owner,
            active_key_id=resolved_key_id,
            secret_dir=params.secret_key_dir,
            catalog=catalog,
            mysql_client=mysql_client,
        )

    @classmethod
    def from_secret_dir(
        cls,
        *,
        owner: ServiceKeyOwner,
        active_key_id: str,
        secret_dir: str | Path,
        public_key_ref: str = "",
        private_key_ref: str = "",
        catalog: list[ServicePublicKeyRecord] | None = None,
        mysql_client: MySQLClient | None = None,
    ) -> "SecretKeyService":
        """从本地密钥目录构建后端密钥服务。"""
        resolved_key_id = active_key_id.strip()
        if not resolved_key_id:
            resolved_key_id = owner.effective_entity_id

        secret_root = Path(secret_dir).expanduser().resolve()
        if not secret_root.exists() or not secret_root.is_dir():
            raise ValueError(f"secret dir does not exist: {secret_root}")

        resolved_public_ref = public_key_ref.strip() or "public.pem"
        resolved_private_ref = private_key_ref.strip() or "private.pem"

        public_key_pem = cls.load_pem_bytes_from_ref(
            resolved_public_ref,
            base_dir=secret_root,
        )
        private_key_pem = cls.load_pem_bytes_from_ref(
            resolved_private_ref,
            base_dir=secret_root,
        )

        cls._ensure_spki_public_key_pem(public_key_pem)
        detected_signature_algorithm = cls._detect_signature_algorithm(public_key_pem)

        cls._ensure_pkcs8_private_key_pem(private_key_pem)
        cls._ensure_private_key_matches_algorithm(
            private_key_pem,
            detected_signature_algorithm,
        )

        normalized_owner = owner.normalized()
        now = time()
        local_public = ServicePublicKeyRecord(
            key_id=resolved_key_id,
            owner=normalized_owner,
            public_key_pem=public_key_pem.decode("utf-8"),
            fingerprint=cls._sha256_hex(public_key_pem),
            status="active",
            created_at=now,
            activated_at=now,
            expires_at=0.0,
            revoked_at=0.0,
        )
        local_private = LocalPrivateKeyRef(
            key_id=resolved_key_id,
            owner=normalized_owner,
            private_key_ref=private_key_pem.decode("utf-8"),
            loaded_at=now,
        )
        return cls(
            local_public_key=local_public,
            local_private_key=local_private,
            catalog=catalog,
            mysql_client=mysql_client,
        )

    @staticmethod
    def load_pem_bytes_from_ref(
        material_ref: str | bytes,
        *,
        base_dir: str | Path | None = None,
    ) -> bytes:
        """支持内联 PEM、base64 文本和文件路径三种形式。"""
        if isinstance(material_ref, bytes):
            return material_ref

        raw_value = material_ref.strip()
        if not raw_value:
            raise ValueError("empty key material reference")

        if "-----BEGIN" in raw_value:
            return raw_value.encode("utf-8")

        if raw_value.startswith("base64:"):
            encoded = raw_value[len("base64:") :].strip()
            if not encoded:
                raise ValueError("empty base64 key material")
            return base64.b64decode(encoded)

        file_path = (
            raw_value[len("file://") :]
            if raw_value.startswith("file://")
            else raw_value
        )
        path = Path(file_path)
        if base_dir is not None and not path.is_absolute():
            path = Path(base_dir) / path
        if not path.exists():
            raise ValueError(f"key material path does not exist: {path}")
        return path.read_bytes()

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

    async def get_public_key(self) -> ServicePublicKeyRecord:
        return self._local_public_key

    async def get_private_key_ref(self) -> LocalPrivateKeyRef:
        return self._local_private_key

    async def lookup_public_key(
        self,
        req: PublicKeyLookupRequest,
    ) -> PublicKeyLookupResult:
        if req is None:
            return PublicKeyLookupResult(
                found=False,
                failure_reason="public key lookup request is required",
                checked_at=time(),
            )

        q = req.normalized()
        if not q.key_id and not q.entity_id and q.owner is None:
            return PublicKeyLookupResult(
                found=False,
                failure_reason="public key lookup criteria is required",
                checked_at=time(),
            )

        if q.key_id:
            result = await self.get_public_key_by_key_id(q.key_id)
            if result.found and result.key and self._key_matches_lookup(result.key, q):
                return PublicKeyLookupResult(
                    found=True,
                    key=result.key,
                    matched_by="key_id",
                    checked_at=time(),
                )

        if q.entity_id:
            result = await self.get_public_key_by_entity_id(q.entity_id)
            if result.found and result.key and self._key_matches_lookup(result.key, q):
                return PublicKeyLookupResult(
                    found=True,
                    key=result.key,
                    matched_by="entity_id",
                    checked_at=time(),
                )

        if q.owner is not None:
            items = await self.get_public_keys_by_owner(q.owner)
            selected: ServicePublicKeyRecord | None = None
            for item in items:
                if not self._key_matches_lookup(item, q):
                    continue
                if selected is None or self._should_prefer_key(item, selected):
                    selected = item

            if selected is not None:
                return PublicKeyLookupResult(
                    found=True,
                    key=selected,
                    matched_by="owner",
                    checked_at=time(),
                )

        return PublicKeyLookupResult(
            found=False,
            failure_reason="public key not found by lookup criteria",
            checked_at=time(),
        )

    async def get_public_key_by_key_id(self, key_id: str) -> PublicKeyLookupResult:
        normalized_key_id = key_id.strip()
        if not normalized_key_id:
            return PublicKeyLookupResult(
                found=False,
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
                failure_reason="key id not found",
                checked_at=time(),
            )
        return PublicKeyLookupResult(found=True, key=key, checked_at=time())

    async def get_public_key_by_entity_id(
        self,
        entity_id: str,
    ) -> PublicKeyLookupResult:
        normalized_entity_id = entity_id.strip()
        if not normalized_entity_id:
            return PublicKeyLookupResult(
                found=False,
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
                failure_reason="entity id not found",
                checked_at=time(),
            )

        return PublicKeyLookupResult(found=True, key=key, checked_at=time())

    async def get_public_keys_by_owner(
        self,
        owner: ServiceKeyOwner,
    ) -> list[ServicePublicKeyRecord]:
        owner = owner.normalized()
        out: list[ServicePublicKeyRecord] = []
        for key in self._catalog_by_key_id.values():
            if not self._match_owner(owner, key.owner):
                continue
            out.append(key)
        if out:
            return out

        db_items = await self._load_public_keys_by_owner(owner)
        for item in db_items:
            self._catalog_by_key_id[item.key_id] = item
        return db_items

    async def _load_public_key_by_id(self, key_id: str) -> ServicePublicKeyRecord | None:
        if self._public_keys_dao is None:
            return None
        row = await self._public_keys_dao.find_by_id(key_id)
        return self._row_to_record(row) if row else None

    async def _load_public_key_by_entity_id(
        self,
        entity_id: str,
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
        self,
        owner: ServiceKeyOwner,
    ) -> list[ServicePublicKeyRecord]:
        if self._public_keys_dao is None:
            return []

        filters: dict[str, str] = {}
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

        return ServicePublicKeyRecord(
            key_id=str(row["key_id"]),
            owner=ServiceKeyOwner(
                entity_type=str(row.get("entity_type") or ""),
                entity_id=str(row.get("entity_id") or ""),
                entity_name=str(row.get("entity_name") or ""),
                instance_id=str(row.get("instance_id") or ""),
                instance_name=str(row.get("instance_name") or ""),
            ).normalized(),
            public_key_pem=str(row["public_key_pem"]),
            fingerprint=str(row["fingerprint"]),
            status=cast(CommKeyStatus, str(row["status"])),
            created_at=created_at,
            activated_at=activated_at,
            expires_at=expires_at,
            revoked_at=revoked_at,
        )

    def _normalize_record(self, item: ServicePublicKeyRecord) -> ServicePublicKeyRecord:
        return ServicePublicKeyRecord(
            key_id=item.key_id,
            owner=item.owner.normalized(),
            public_key_pem=item.public_key_pem,
            fingerprint=item.fingerprint,
            status=item.status,
            created_at=item.created_at,
            activated_at=item.activated_at,
            expires_at=item.expires_at,
            revoked_at=item.revoked_at,
        )

    def _pick_catalog_key_by_entity_id(self, entity_id: str) -> ServicePublicKeyRecord | None:
        preferred: ServicePublicKeyRecord | None = None
        for key in self._catalog_by_key_id.values():
            if key.owner.effective_entity_id != entity_id:
                continue
            if preferred is None or self._should_prefer_key(key, preferred):
                preferred = key
        return preferred

    @staticmethod
    def _match_owner(expected: ServiceKeyOwner, actual: ServiceKeyOwner) -> bool:
        expected = expected.normalized()
        actual = actual.normalized()
        if expected.entity_type and expected.entity_type != actual.entity_type:
            return False
        if (
            expected.effective_entity_id
            and expected.effective_entity_id != actual.effective_entity_id
        ):
            return False
        if (
            expected.effective_entity_name
            and expected.effective_entity_name != actual.effective_entity_name
        ):
            return False
        if expected.instance_id and expected.instance_id != actual.instance_id:
            return False
        if expected.instance_name and expected.instance_name != actual.instance_name:
            return False
        return True

    def _key_matches_lookup(
        self,
        key: ServicePublicKeyRecord,
        query: PublicKeyLookupRequest,
    ) -> bool:
        if query.key_id and key.key_id != query.key_id:
            return False
        if query.entity_id and key.owner.effective_entity_id != query.entity_id:
            return False
        if query.owner is not None and not self._match_owner(query.owner, key.owner):
            return False
        if query.require_active and key.status != "active":
            return False
        return True

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

    @staticmethod
    def _sha256_hex(content: bytes) -> str:
        return hashlib.sha256(content).hexdigest()

    @staticmethod
    def _detect_signature_algorithm(public_key_pem: bytes) -> SignatureAlgorithm:
        parsed = serialization.load_pem_public_key(public_key_pem)
        if isinstance(parsed, ed25519.Ed25519PublicKey):
            return cast(SignatureAlgorithm, "ed25519")
        if isinstance(parsed, ec.EllipticCurvePublicKey):
            if not isinstance(parsed.curve, ec.SECP256R1):
                raise ValueError("unsupported ecdsa curve, only p256 is allowed")
            return cast(SignatureAlgorithm, "ecdsa_p256_sha256")
        if isinstance(parsed, rsa.RSAPublicKey):
            return cast(SignatureAlgorithm, "rsa_pss_sha256")
        raise ValueError("unsupported public key type")

    @staticmethod
    def _ensure_pkcs8_private_key_pem(private_key_pem: bytes) -> None:
        text = private_key_pem.decode("utf-8", errors="ignore")
        if "-----BEGIN PRIVATE KEY-----" not in text:
            raise ValueError("private key must be unencrypted PKCS#8 PEM")
        serialization.load_pem_private_key(private_key_pem, password=None)

    @staticmethod
    def _ensure_spki_public_key_pem(public_key_pem: bytes) -> None:
        text = public_key_pem.decode("utf-8", errors="ignore")
        if "-----BEGIN PUBLIC KEY-----" not in text:
            raise ValueError("public key must be SPKI PEM")
        serialization.load_pem_public_key(public_key_pem)

    @staticmethod
    def _ensure_private_key_matches_algorithm(
        private_key_pem: bytes,
        algorithm: SignatureAlgorithm,
    ) -> None:
        parsed = serialization.load_pem_private_key(private_key_pem, password=None)
        if algorithm == "ed25519":
            if not isinstance(parsed, ed25519.Ed25519PrivateKey):
                raise ValueError("private key type does not match ed25519")
            return

        if algorithm == "ecdsa_p256_sha256":
            if not isinstance(parsed, ec.EllipticCurvePrivateKey):
                raise ValueError("private key type does not match ecdsa")
            if not isinstance(parsed.curve, ec.SECP256R1):
                raise ValueError("ecdsa private key must use p256 curve")
            return

        if algorithm == "rsa_pss_sha256":
            if not isinstance(parsed, rsa.RSAPrivateKey):
                raise ValueError("private key type does not match rsa")
            return

        raise ValueError(f"unsupported signature algorithm: {algorithm}")
