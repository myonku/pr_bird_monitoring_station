import base64
import hashlib
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

from src.iface.auth_interface import ISecretKeyManager
from src.models.auth.auth import LocalTrustMaterial, SignatureAlgorithm
from src.utils.crypto_utils import CryptoUtils


class SecretKeyUtils(ISecretKeyManager):
    """本地密钥管理工具。

    默认约定密钥放在模块根目录的 secret_keys 下：
    - {key_id}.private.pem: 私钥（PKCS#8 PEM）
    - {key_id}.public.pem: 公钥（SPKI PEM）
    """

    def __init__(
        self,
        local_trust_material: LocalTrustMaterial,
        base_dir: str | Path | None = None,
        signature_algorithm: SignatureAlgorithm | None = None,
    ):
        self._local = local_trust_material
        self._base_dir = Path(base_dir).resolve() if base_dir is not None else None
        self._validate_material(
            local_trust_material,
            expected_algorithm=signature_algorithm,
        )

    @classmethod
    def from_secret_dir(
        cls,
        *,
        device_id: str,
        active_key_id: str,
        signature_algorithm: SignatureAlgorithm | None = None,
        secret_dir: str | Path = "secret_keys",
        module_root: str | Path | None = None,
    ) -> "SecretKeyUtils":
        """从模块根目录的 secret_keys 中构建本地密钥管理器。"""
        secret_root = cls.resolve_secret_dir(secret_dir=secret_dir, module_root=module_root)
        if not secret_root.exists() or not secret_root.is_dir():
            raise ValueError(f"secret dir does not exist: {secret_root}")

        public_path = secret_root / f"{active_key_id}.public.pem"
        private_path = secret_root / f"{active_key_id}.private.pem"
        if not public_path.exists():
            raise ValueError(f"public key does not exist: {public_path}")
        if not private_path.exists():
            raise ValueError(f"private key does not exist: {private_path}")

        public_pem = public_path.read_bytes()
        cls._ensure_spki_public_key_pem(public_pem)

        material = LocalTrustMaterial(
            device_id=device_id,
            key_id=active_key_id,
            private_key_ref=str(private_path),
            public_key_pem=str(public_path),
            fingerprint=cls._sha256_hex(public_pem),
        )
        return cls(
            local_trust_material=material,
            base_dir=secret_root,
            signature_algorithm=signature_algorithm,
        )

    @staticmethod
    def resolve_module_root() -> Path:
        return Path(__file__).resolve().parents[2]

    @classmethod
    def resolve_secret_dir(
        cls,
        *,
        secret_dir: str | Path = "secret_keys",
        module_root: str | Path | None = None,
    ) -> Path:
        root = Path(module_root).resolve() if module_root is not None else cls.resolve_module_root()
        candidate = Path(secret_dir)
        if not candidate.is_absolute():
            candidate = root / candidate
        return candidate.resolve()

    def get_local_trust_material(self) -> LocalTrustMaterial:
        return self._local

    def get_private_key_pem(self) -> bytes:
        if not self._local.private_key_ref:
            raise ValueError("private key ref is empty")
        return self.load_pem_bytes_from_ref(self._local.private_key_ref, base_dir=self._base_dir)

    def get_public_key_pem(self) -> bytes:
        return self.load_pem_bytes_from_ref(self._local.public_key_pem, base_dir=self._base_dir)

    @staticmethod
    def load_pem_bytes_from_ref(
        material_ref: str | bytes,
        base_dir: str | Path | None = None,
    ) -> bytes:
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
        if base_dir is not None and not path.is_absolute():
            path = Path(base_dir) / path
        if not path.exists():
            raise ValueError(f"key material path does not exist: {path}")
        return path.read_bytes()

    @staticmethod
    def _sha256_hex(content: bytes) -> str:
        return hashlib.sha256(content).hexdigest()

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

    def _validate_material(
        self,
        material: LocalTrustMaterial,
        *,
        expected_algorithm: SignatureAlgorithm | None = None,
    ) -> None:
        public_key_pem = self.load_pem_bytes_from_ref(material.public_key_pem, base_dir=self._base_dir)
        self._ensure_spki_public_key_pem(public_key_pem)
        detected_algorithm = CryptoUtils.detect_signature_algorithm_from_public_key(public_key_pem)
        if expected_algorithm is not None and detected_algorithm != expected_algorithm:
            raise ValueError(
                f"signature algorithm mismatch for key_id={material.key_id}: "
                f"expected={expected_algorithm} detected={detected_algorithm}"
            )

        if not material.private_key_ref:
            raise ValueError(f"private key ref is required for key_id={material.key_id}")

        private_key_pem = self.load_pem_bytes_from_ref(
            material.private_key_ref,
            base_dir=self._base_dir,
        )
        self._ensure_pkcs8_private_key_pem(private_key_pem)
        self._ensure_private_key_matches_algorithm(private_key_pem, detected_algorithm)
