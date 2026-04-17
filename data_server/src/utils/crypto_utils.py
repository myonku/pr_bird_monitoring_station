import base64
import hashlib
import hmac
import os
import struct
from typing import Literal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import (
    ec,
    ed25519,
    padding,
    rsa,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.ciphers import aead as _aead


XChaCha20Poly1305 = getattr(_aead, "XChaCha20Poly1305", None)


KEYSIZE_AES = Literal[16, 32]  # AES-128 或 AES-256 的密钥长度（以字节为单位）
KEYSIZE_RSA = Literal[2048, 4096]  # RSA 密钥长度（以位为单位）


class CryptoUtils:
    """提供对称加密、非对称加密、签名验签等常用密码学操作的工具类。"""

    @staticmethod
    def derive_random_symmetric_key(
        key_size: KEYSIZE_AES, output_base64: bool = True
    ) -> str | bytes:
        """生成指定长度的随机对称密钥（AES）。返回 Base64 编码的字符串或原始字节数据。"""
        key = CryptoUtils.derive_random_symmetric_key_bytes(key_size)
        if output_base64:
            return base64.b64encode(key).decode("ascii")
        return key

    @staticmethod
    def derive_random_symmetric_key_bytes(key_size: KEYSIZE_AES) -> bytes:
        """生成指定长度的随机对称密钥（AES），返回原始字节。"""
        if key_size not in (16, 32):
            raise ValueError(f"unsupported symmetric key size: {key_size}")
        return os.urandom(int(key_size))

    @staticmethod
    def derive_random_asymmetric_key(
        key_size: KEYSIZE_RSA, output_base64: bool = True
    ) -> tuple[bytes, bytes] | tuple[str, str]:
        """生成指定长度的随机非对称密钥对（RSA）。
        返回 X.509 SPKI 公钥和 PKCS#8 私钥，格式为 Base64 编码字符串或原始 PEM 字节。
        """
        public_key, private_key = CryptoUtils.derive_random_asymmetric_key_bytes(
            key_size
        )
        if output_base64:
            return public_key.decode("ascii"), private_key.decode("ascii")
        return public_key, private_key

    @staticmethod
    def derive_random_asymmetric_key_bytes(
        key_size: KEYSIZE_RSA,
    ) -> tuple[bytes, bytes]:
        """生成 RSA 密钥对，返回 SPKI 公钥与 PKCS#8 私钥的 PEM 字节。"""
        if key_size not in (2048, 4096):
            raise ValueError(f"unsupported asymmetric key size: {key_size}")

        private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=int(key_size)
        )
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        public_pem = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return public_pem, private_pem

    @staticmethod
    def encrypt_with_symmetric_key(plaintext: str, key: bytes) -> str:
        """使用 AES-GCM 对称密钥加密数据，返回 Base64 编码密文。"""
        return CryptoUtils.encrypt_with_symmetric_key_and_aad(plaintext, key, None)

    @staticmethod
    def encrypt_with_symmetric_key_and_aad(
        plaintext: str, key: bytes, aad: bytes | None
    ) -> str:
        """使用 AES-GCM + AAD 加密。输出为 nonce|ciphertext 的 Base64。"""
        aes_gcm = AESGCM(key)
        nonce = os.urandom(12)
        encrypted = aes_gcm.encrypt(nonce, plaintext.encode("utf-8"), aad)
        return base64.b64encode(nonce + encrypted).decode("ascii")

    @staticmethod
    def decrypt_with_symmetric_key(ciphertext: str, key: bytes) -> str:
        """使用 AES-GCM 对称密钥解密数据。"""
        return CryptoUtils.decrypt_with_symmetric_key_and_aad(ciphertext, key, None)

    @staticmethod
    def decrypt_with_symmetric_key_and_aad(
        ciphertext: str, key: bytes, aad: bytes | None
    ) -> str:
        """使用 AES-GCM + AAD 解密。"""
        raw = base64.b64decode(ciphertext)
        if len(raw) < 12:
            raise ValueError("invalid ciphertext length")
        nonce = raw[:12]
        payload = raw[12:]
        aes_gcm = AESGCM(key)
        plain = aes_gcm.decrypt(nonce, payload, aad)
        return plain.decode("utf-8")

    @staticmethod
    def encrypt_with_cipher_suite(
        cipher_suite: str, plaintext: str, key: bytes, aad: bytes | None
    ) -> str:
        """按协商密码套件加密。"""
        if cipher_suite in ("aes_128_gcm", "aes_256_gcm", ""):
            return CryptoUtils.encrypt_with_symmetric_key_and_aad(plaintext, key, aad)

        if cipher_suite == "chacha20_poly1305":
            if XChaCha20Poly1305 is not None:
                nonce = os.urandom(24)
                aead = XChaCha20Poly1305(key)
                encrypted = aead.encrypt(nonce, plaintext.encode("utf-8"), aad)
                return base64.b64encode(nonce + encrypted).decode("ascii")

            nonce = os.urandom(12)
            aead = ChaCha20Poly1305(key)
            encrypted = aead.encrypt(nonce, plaintext.encode("utf-8"), aad)
            return base64.b64encode(nonce + encrypted).decode("ascii")

        raise ValueError(f"unsupported cipher suite: {cipher_suite}")

    @staticmethod
    def decrypt_with_cipher_suite(
        cipher_suite: str, ciphertext: str, key: bytes, aad: bytes | None
    ) -> str:
        """按协商密码套件解密。"""
        if cipher_suite in ("aes_128_gcm", "aes_256_gcm", ""):
            return CryptoUtils.decrypt_with_symmetric_key_and_aad(ciphertext, key, aad)

        if cipher_suite == "chacha20_poly1305":
            raw = base64.b64decode(ciphertext)

            if XChaCha20Poly1305 is not None and len(raw) >= 24:
                nonce = raw[:24]
                payload = raw[24:]
                plain = XChaCha20Poly1305(key).decrypt(nonce, payload, aad)
                return plain.decode("utf-8")

            if len(raw) < 12:
                raise ValueError("invalid ciphertext length")
            nonce = raw[:12]
            payload = raw[12:]
            plain = ChaCha20Poly1305(key).decrypt(nonce, payload, aad)
            return plain.decode("utf-8")

        raise ValueError(f"unsupported cipher suite: {cipher_suite}")

    @staticmethod
    def encrypt_with_asymmetric_key(plaintext: str, public_key: bytes) -> str:
        """使用 RSA-OAEP(SHA256) 公钥加密。"""
        return CryptoUtils.encrypt_with_public_key(plaintext, public_key)

    @staticmethod
    def encrypt_with_public_key(plaintext: str, public_key_pem: bytes) -> str:
        """使用 RSA-OAEP(SHA256) 公钥加密。"""
        parsed = serialization.load_pem_public_key(public_key_pem)
        if not isinstance(parsed, rsa.RSAPublicKey):
            raise ValueError("public key is not rsa")

        encrypted = parsed.encrypt(
            plaintext.encode("utf-8"),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        return base64.b64encode(encrypted).decode("ascii")

    @staticmethod
    def decrypt_with_asymmetric_key(ciphertext: str, private_key: bytes) -> str:
        """使用 RSA-OAEP(SHA256) 私钥解密。"""
        return CryptoUtils.decrypt_with_private_key(ciphertext, private_key)

    @staticmethod
    def decrypt_with_private_key(ciphertext: str, private_key_pem: bytes) -> str:
        """使用 RSA-OAEP(SHA256) 私钥解密。"""
        private_key = serialization.load_pem_private_key(private_key_pem, password=None)
        if not isinstance(private_key, rsa.RSAPrivateKey):
            raise ValueError("private key is not rsa")

        raw = base64.b64decode(ciphertext)
        plaintext = private_key.decrypt(
            raw,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        return plaintext.decode("utf-8")

    @staticmethod
    def sign_by_algorithm(
        algorithm: str, message: bytes, private_key_pem: bytes
    ) -> str:
        """按算法签名，返回 Base64 编码签名。"""
        private_key = CryptoUtils._parse_private_key(private_key_pem)

        match algorithm:
            case "ed25519":
                if not isinstance(private_key, ed25519.Ed25519PrivateKey):
                    raise ValueError("private key is not ed25519")
                signature = private_key.sign(message)
                return base64.b64encode(signature).decode("ascii")

            case "ecdsa_p256_sha256":
                if not isinstance(private_key, ec.EllipticCurvePrivateKey):
                    raise ValueError("private key is not ecdsa")
                signature = private_key.sign(message, ec.ECDSA(hashes.SHA256()))
                return base64.b64encode(signature).decode("ascii")

            case "rsa_pss_sha256":
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
            case _:
                raise ValueError(f"unsupported signature algorithm: {algorithm}")

    @staticmethod
    def verify_by_algorithm(
        algorithm: str, message: bytes, signature_b64: str, public_key_pem: bytes
    ) -> None:
        """按算法验签，失败时抛出 ValueError。"""
        signature = base64.b64decode(signature_b64)
        public_key = CryptoUtils._parse_public_key(public_key_pem)

        try:
            match algorithm:
                case "ed25519":
                    if not isinstance(public_key, ed25519.Ed25519PublicKey):
                        raise ValueError("public key is not ed25519")
                    public_key.verify(signature, message)
                    return

                case "ecdsa_p256_sha256":
                    if not isinstance(public_key, ec.EllipticCurvePublicKey):
                        raise ValueError("public key is not ecdsa")
                    public_key.verify(
                        signature, message, ec.ECDSA(hashes.SHA256())
                    )
                    return

                case "rsa_pss_sha256":
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
        except InvalidSignature as exc:
            raise ValueError("signature verification failed") from exc

        raise ValueError(f"unsupported signature algorithm: {algorithm}")

    @staticmethod
    def derive_session_key_by_handshake(
        key_exchange: str,
        cipher_suite: str,
        initiator_ephemeral: str,
        responder_ephemeral: str,
        initiator_nonce: str,
        responder_nonce: str,
    ) -> str:
        """根据握手材料和协商参数派生会话密钥，返回 Base64。"""
        key_len = 16 if cipher_suite == "aes_128_gcm" else 32
        material = (
            f"{key_exchange}|{initiator_ephemeral}|{responder_ephemeral}|"
            f"{initiator_nonce}|{responder_nonce}"
        ).encode("utf-8")
        seed = hashlib.sha512(material).digest()

        output = bytearray()
        counter = 1
        while len(output) < key_len:
            counter_bytes = struct.pack(">I", counter)
            block = hmac.new(seed, counter_bytes, hashlib.sha256).digest()
            output.extend(block)
            counter += 1

        return base64.b64encode(bytes(output[:key_len])).decode("ascii")

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
