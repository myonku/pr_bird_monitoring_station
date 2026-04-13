from __future__ import annotations

from typing import Literal

from msgspec import Struct


CommKeyStatus = Literal["active", "expired", "revoked"]
SignatureAlgorithm = Literal["ecdsa_p256_sha256", "ed25519", "rsa_pss_sha256"]
CipherSuite = Literal["chacha20_poly1305", "aes_256_gcm", "aes_128_gcm"]


class ServiceKeyOwner(Struct, kw_only=True):
    """表示通信密钥所有者，统一使用 entity 维度。"""

    entity_type: str = ""
    entity_id: str = ""
    entity_name: str = ""
    instance_id: str = ""
    instance_name: str = ""

    @property
    def effective_entity_id(self) -> str:
        return self.entity_id

    @property
    def effective_entity_name(self) -> str:
        return self.entity_name or self.entity_id

    def normalized(self) -> "ServiceKeyOwner":
        entity_type = self.entity_type.strip().lower()
        entity_id = self.entity_id.strip()
        entity_name = self.entity_name.strip() or entity_id
        return ServiceKeyOwner(
            entity_type=entity_type,
            entity_id=entity_id,
            entity_name=entity_name,
            instance_id=self.instance_id.strip(),
            instance_name=self.instance_name.strip(),
        )


class ServicePublicKeyRecord(Struct, kw_only=True):
    """表示一个服务公钥目录记录。"""

    key_id: str
    owner: ServiceKeyOwner

    public_key_pem: str
    fingerprint: str

    status: CommKeyStatus

    created_at: float
    activated_at: float
    expires_at: float
    revoked_at: float


class LocalPrivateKeyRef(Struct, kw_only=True):
    """表示一个本地私钥引用。"""

    key_id: str
    owner: ServiceKeyOwner

    private_key_ref: str
    loaded_at: float


class PublicKeyLookupRequest(Struct, kw_only=True):
    """统一公钥目录查询请求。"""

    key_id: str = ""
    entity_id: str = ""
    owner: ServiceKeyOwner | None = None
    require_active: bool = False

    def normalized(self) -> "PublicKeyLookupRequest":
        key_id = self.key_id.strip()
        entity_id = self.entity_id.strip()
        owner = self.owner.normalized() if self.owner is not None else None
        if owner is not None and not entity_id:
            entity_id = owner.effective_entity_id
        return PublicKeyLookupRequest(
            key_id=key_id,
            entity_id=entity_id,
            owner=owner,
            require_active=self.require_active,
        )


class PublicKeyLookupResult(Struct, kw_only=True):
    """公钥目录查询结果。"""

    found: bool
    key: ServicePublicKeyRecord | None = None
    matched_by: str = ""
    failure_reason: str = ""
    checked_at: float = 0.0
