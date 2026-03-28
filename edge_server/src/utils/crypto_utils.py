import base64
from datetime import UTC, datetime

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa

from src.models.auth_models import (
    BootstrapChallenge,
    SignatureAlgorithm,
)


class CryptoUtils:
    """边缘认证密码学工具套件（功能方法集合）。"""

    @staticmethod
    def sign_by_algorithm(
        algorithm: SignatureAlgorithm,
        message: bytes,
        private_key_pem: bytes,
    ) -> str:
        """按算法对字节进行签名，返回 base64 签名字符串（与服务端算法保持一致）。"""
        private_key = CryptoUtils._parse_private_key(private_key_pem)

        if algorithm == "ed25519":
            if not isinstance(private_key, ed25519.Ed25519PrivateKey):
                raise ValueError("private key is not ed25519")
            signature = private_key.sign(message)
            return base64.b64encode(signature).decode("ascii")

        if algorithm == "ecdsa_p256_sha256":
            if not isinstance(private_key, ec.EllipticCurvePrivateKey):
                raise ValueError("private key is not ecdsa")
            signature = private_key.sign(message, ec.ECDSA(hashes.SHA256()))
            return base64.b64encode(signature).decode("ascii")

        if algorithm == "rsa_pss_sha256":
            if not isinstance(private_key, rsa.RSAPrivateKey):
                raise ValueError("private key is not rsa")
            signature = private_key.sign(
                message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )
            return base64.b64encode(signature).decode("ascii")

        raise ValueError(f"unsupported signature algorithm: {algorithm}")

    @staticmethod
    def verify_by_algorithm(
        algorithm: SignatureAlgorithm,
        message: bytes,
        signature_b64: str,
        public_key_pem: bytes,
    ) -> None:
        """验证签名，验证失败时抛出 ValueError。"""
        signature = base64.b64decode(signature_b64)
        public_key = CryptoUtils._parse_public_key(public_key_pem)

        try:
            if algorithm == "ed25519":
                if not isinstance(public_key, ed25519.Ed25519PublicKey):
                    raise ValueError("public key is not ed25519")
                public_key.verify(signature, message)
                return

            if algorithm == "ecdsa_p256_sha256":
                if not isinstance(public_key, ec.EllipticCurvePublicKey):
                    raise ValueError("public key is not ecdsa")
                public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
                return

            if algorithm == "rsa_pss_sha256":
                if not isinstance(public_key, rsa.RSAPublicKey):
                    raise ValueError("public key is not rsa")
                public_key.verify(
                    signature,
                    message,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH,
                    ),
                    hashes.SHA256(),
                )
                return
        except Exception as exc:
            if isinstance(exc, InvalidSignature):
                raise ValueError("signature verification failed") from exc
            raise

        raise ValueError(f"unsupported signature algorithm: {algorithm}")

    @staticmethod
    def build_bootstrap_signature_payload(
        challenge: BootstrapChallenge,
        *,
        key_id: str,
        entity_type: str,
        entity_id: str,
    ) -> bytes:
        """构建与认证中心校验器兼容的标准化启动签名载荷。

        载荷格式：
        challenge_id|issuer|audience|entity_type|entity_id|key_id|nonce|issued_at_rfc3339nano|expires_at_rfc3339nano
        """
        parts = [
            challenge.challenge_id,
            challenge.issuer,
            challenge.audience,
            entity_type,
            entity_id,
            key_id,
            challenge.nonce,
            CryptoUtils.unix_ts_to_rfc3339nano(challenge.issued_at),
            CryptoUtils.unix_ts_to_rfc3339nano(challenge.expires_at),
        ]
        return "|".join(parts).encode("utf-8")

    @staticmethod
    def unix_ts_to_rfc3339nano(ts: float) -> str:
        """将 Unix 秒时间戳转换为 UTC 的 RFC3339Nano 字符串。

        Go 校验器使用 time.RFC3339Nano 格式，本函数保持相同的小数纳秒裁剪行为。
        """
        sec = int(ts)
        nanos = int(round((ts - sec) * 1_000_000_000))
        if nanos >= 1_000_000_000:
            sec += 1
            nanos -= 1_000_000_000
        if nanos < 0:
            sec -= 1
            nanos += 1_000_000_000

        dt = datetime.fromtimestamp(sec, tz=UTC)
        base = dt.strftime("%Y-%m-%dT%H:%M:%S")
        if nanos == 0:
            return f"{base}Z"
        frac = f"{nanos:09d}".rstrip("0")
        return f"{base}.{frac}Z"

    @staticmethod
    def _parse_private_key(private_key_pem: bytes):
        try:
            return serialization.load_pem_private_key(private_key_pem, password=None)
        except ValueError as exc:
            raise ValueError("unsupported private key format") from exc

    @staticmethod
    def _parse_public_key(public_key_pem: bytes):
        try:
            return serialization.load_pem_public_key(public_key_pem)
        except ValueError as exc:
            raise ValueError("invalid public key pem") from exc
