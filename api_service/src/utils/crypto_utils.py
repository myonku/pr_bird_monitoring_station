import os, base64, hmac, time
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives import serialization

HKDF_LEN = 64
INFO_MASTER = b"bms:master"
INFO_C2S = b"bms:c2s"
INFO_S2C = b"bms:s2c"
LABEL_VERIFY = b"bms:verify:"


def now_epoch() -> float:
    return time.time()


def derive_session_keys_static(
    client_pub_b64: str,
    server_priv_bytes: bytes,
    session_id: str,
    server_pub_b64: str | None = None,
    # 其他可能需要的参数，如时间戳、客户端IP等，可以在函数签名中添加
) -> tuple[bytes, bytes, str]:
    """
    静态服务端私钥 + 客户端临时公钥 -> 预主密钥
    使用 session_id 作为 HKDF 的上下文绑定；
    返回 (c2s_key, s2c_key, fingerprint)
    """
    ...


def compute_verify_hmac(c2s_key: bytes, s2c_key: bytes, server_nonce_b64: str) -> str:
    """计算HMAC"""
    server_nonce = base64.b64decode(server_nonce_b64)
    mac = hmac.new(c2s_key + s2c_key, LABEL_VERIFY + server_nonce, digestmod="sha256")
    return mac.hexdigest()


def aesgcm_encrypt(
    key: bytes, plaintext: bytes, aad: bytes | None = None
) -> tuple[str, str]:
    """对称加密"""
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, plaintext, aad)
    return base64.b64encode(nonce).decode(), base64.b64encode(ct).decode()


def aesgcm_decrypt(
    key: bytes, nonce_b64: str, ct_b64: str, aad: bytes | None = None
) -> bytes:
    """对称解密"""
    nonce = base64.b64decode(nonce_b64)
    ct = base64.b64decode(ct_b64)
    return AESGCM(key).decrypt(nonce, ct, aad)
