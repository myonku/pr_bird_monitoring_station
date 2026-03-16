from typing import Literal


KEYSIZE_AES = Literal[16, 32]  # AES-128 或 AES-256 的密钥长度（以字节为单位）
KEYSIZE_RSA = Literal[2048, 4096]  # RSA 密钥长度（以位为单位）


class CryptoUtils:

    @staticmethod
    def derive_random_symmetric_key(
        key_size: KEYSIZE_AES, output_base64: bool = True
    ) -> str | bytes:
        """生成指定长度的随机对称密钥（AES）。返回 Base64 编码的字符串或原始字节数据。"""
        ...

    @staticmethod
    def derive_random_asymmetric_key(
        key_size: KEYSIZE_RSA, output_base64: bool = True
    ) -> tuple[bytes, bytes] | tuple[str, str]:
        """生成指定长度的随机非对称密钥对（RSA）。返回 X.509/SPKI 格式的公钥和 PKCS#8 格式的私钥，
        默认以 PEM 格式的 Base64 编码字符串形式输出。
        """
        ...

    @staticmethod
    def encrypt_with_symmetric_key(plaintext: str, key: bytes) -> str:
        """使用对称密钥加密数据，返回 Base64 编码的密文字符串。"""
        ...
    
    @staticmethod
    def decrypt_with_symmetric_key(ciphertext: str, key: bytes) -> str:
        """使用对称密钥解密数据，输入为 Base64 编码的密文字符串，返回解密后的明文字符串（UTF-8 编码）。"""
        ...
    
    @staticmethod
    def encrypt_with_asymmetric_key(plaintext: str, public_key: bytes) -> str:
        """使用非对称密钥加密数据，返回 Base64 编码的密文字符串。"""
        ...
    
    @staticmethod
    def decrypt_with_asymmetric_key(ciphertext: str, private_key: bytes) -> str:
        """使用非对称密钥解密数据，输入为 Base64 编码的密文字符串，返回解密后的明文字符串（UTF-8 编码）。"""
        ...