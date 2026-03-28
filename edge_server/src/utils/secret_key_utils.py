from __future__ import annotations

import base64
from pathlib import Path
from time import time

from src.models.auth_models import (
    BootstrapChallenge,
    LocalTrustMaterial,
    SignedBootstrapProof,
)
from src.utils.crypto_utils import CryptoUtils


class SecretKeyUtils:
    """本地密钥管理工具，提供本地密钥查询能力。"""

    def __init__(
        self,
        local_trust_material: LocalTrustMaterial,
        catalog: list[LocalTrustMaterial] | None = None,
    ):
        self._local = local_trust_material
        self._catalog_by_key_id: dict[str, LocalTrustMaterial] = {
            local_trust_material.key_id: local_trust_material,
        }
        for item in catalog or []:
            self._catalog_by_key_id[item.key_id] = item

    def get_local_trust_material(self) -> LocalTrustMaterial:
        return self._local

    def get_active_key_id(self) -> str:
        return self._local.key_id

    def get_public_key_by_key_id(self, key_id: str) -> LocalTrustMaterial | None:
        return self._catalog_by_key_id.get(key_id)

    def get_public_keys_by_device(self, device_id: str) -> list[LocalTrustMaterial]:
        return [v for v in self._catalog_by_key_id.values() if v.device_id == device_id]

    def get_private_key_pem(self, key_id: str | None = None) -> bytes:
        material = self._resolve_signing_material(key_id)
        return self.load_pem_bytes_from_ref(material.private_key_ref)

    def get_public_key_pem(self, key_id: str | None = None) -> bytes:
        material = self._resolve_signing_material(key_id)
        return self.load_pem_bytes_from_ref(material.public_key_pem)

    def sign_bootstrap_challenge(
        self,
        challenge: BootstrapChallenge,
        *,
        signed_at: float | None = None,
    ) -> SignedBootstrapProof:
        key_id = challenge.key_id or self._local.key_id
        material = self._resolve_signing_material(key_id)
        entity_type = challenge.entity_type or "device"
        entity_id = challenge.entity_id or material.device_id

        payload = CryptoUtils.build_bootstrap_signature_payload(
            challenge,
            key_id=material.key_id,
            entity_type=entity_type,
            entity_id=entity_id,
        )
        signature = CryptoUtils.sign_by_algorithm(
            material.signature_algorithm,
            payload,
            self.get_private_key_pem(material.key_id),
        )
        return SignedBootstrapProof(
            challenge_id=challenge.challenge_id,
            device_id=material.device_id,
            key_id=material.key_id,
            signature=signature,
            signature_algorithm=material.signature_algorithm,
            signed_at=signed_at if signed_at is not None else time(),
        )

    @staticmethod
    def load_pem_bytes_from_ref(material_ref: str | bytes) -> bytes:
        """从内联文本、base64 内容或本地文件路径加载 PEM 字节。"""
        if isinstance(material_ref, bytes):
            return material_ref

        value = material_ref.strip()
        if not value:
            raise ValueError("empty key material reference")

        if "-----BEGIN" in value:
            return value.encode("utf-8")

        if value.startswith("base64:"):
            raw = value[len("base64:") :].strip()
            if not raw:
                raise ValueError("empty base64 key material")
            return base64.b64decode(raw)

        file_path = value[len("file://") :] if value.startswith("file://") else value
        path = Path(file_path)
        if not path.exists():
            raise ValueError(f"key material path does not exist: {file_path}")
        return path.read_bytes()

    def _resolve_signing_material(self, key_id: str | None) -> LocalTrustMaterial:
        if not key_id:
            return self._local
        found = self._catalog_by_key_id.get(key_id)
        if found is None:
            raise ValueError(f"key id not found: {key_id}")
        return found
