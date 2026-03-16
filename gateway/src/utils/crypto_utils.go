package utils

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
)

type KeySize int

const (
	KeySizeAES128  KeySize = 16   // 128 bits = 16 bytes
	KeySizeAES256  KeySize = 32   // 256 bits = 32 bytes
	KeySizeRSA2048 KeySize = 2048 // 2048 bits = 256 bytes
	KeySizeRSA4096 KeySize = 4096 // 4096 bits = 512 bytes
)

// 用于收纳常用的加密相关工具函数。
type CryptoUtils struct {
}

// DeriveRandomSymmetricKey 生成一个确定长度的随机的 AES 对称密钥，返回 Base64 编码的字符串形式。
func (c *CryptoUtils) DeriveRandomSymmetricKey(keySize KeySize) (string, error) {
	key, err := c.DeriveRandomSymmetricKeyBytes(keySize)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(key), nil
}

// DeriveRandomSymmetricKeyBytes 生成一个确定长度的随机的 AES 对称密钥，返回原始字节切片形式。
func (c *CryptoUtils) DeriveRandomSymmetricKeyBytes(keySize KeySize) ([]byte, error) {
	if keySize != KeySizeAES128 && keySize != KeySizeAES256 {
		return nil, fmt.Errorf("unsupported symmetric key size: %d", keySize)
	}

	buf := make([]byte, int(keySize))
	if _, err := io.ReadFull(rand.Reader, buf); err != nil {
		return nil, err
	}

	return buf, nil
}

// DeriveRandomAsymmetricKey 生成一对随机的 RSA 非对称密钥。
// 返回 X.509/SPKI 格式的公钥和 PKCS#8 格式的私钥，均为 PEM 编码的字符串形式。
func (c *CryptoUtils) DeriveRandomAsymmetricKey(keySize KeySize) (string, string, error) {
	pub, pri, err := c.DeriveRandomAsymmetricKeyBytes(keySize)
	if err != nil {
		return "", "", err
	}

	return string(pub), string(pri), nil
}

// DeriveRandomAsymmetricKeyBytes 生成一对随机的 RSA 非对称密钥。
// 返回 X.509/SPKI 格式的公钥和 PKCS#8 格式的私钥，均为原始字节切片形式。
func (c *CryptoUtils) DeriveRandomAsymmetricKeyBytes(keySize KeySize) ([]byte, []byte, error) {
	if keySize != KeySizeRSA2048 && keySize != KeySizeRSA4096 {
		return nil, nil, fmt.Errorf("unsupported asymmetric key size: %d", keySize)
	}

	priv, err := rsa.GenerateKey(rand.Reader, int(keySize))
	if err != nil {
		return nil, nil, err
	}

	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, nil, err
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return nil, nil, err
	}

	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
	priPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})

	return pubPEM, priPEM, nil
}

// EncryptWithSymmetricKey 使用指定的 AES 对称密钥加密明文字符串，返回 Base64 编码的密文字符串。
func (c *CryptoUtils) EncryptWithSymmetricKey(plainText string, key []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	cipherBytes := gcm.Seal(nil, nonce, []byte(plainText), nil)
	out := append(nonce, cipherBytes...)

	return base64.StdEncoding.EncodeToString(out), nil
}

// DecryptWithSymmetricKey 使用指定的 AES 对称密钥解密 Base64 编码的密文字符串，返回明文字符串。
func (c *CryptoUtils) DecryptWithSymmetricKey(cipherText string, key []byte) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(cipherText)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	if len(raw) < gcm.NonceSize() {
		return "", errors.New("invalid ciphertext length")
	}

	nonce := raw[:gcm.NonceSize()]
	cipherBytes := raw[gcm.NonceSize():]

	plain, err := gcm.Open(nil, nonce, cipherBytes, nil)
	if err != nil {
		return "", err
	}

	return string(plain), nil
}

// EncryptWithPublicKey 使用指定的 RSA 公钥加密明文字符串，返回 Base64 编码的密文字符串。
func (c *CryptoUtils) EncryptWithPublicKey(plainText string, publicKey []byte) (string, error) {
	block, _ := pem.Decode(publicKey)
	if block == nil {
		return "", errors.New("invalid public key pem")
	}

	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return "", err
	}

	rsaPub, ok := parsed.(*rsa.PublicKey)
	if !ok {
		return "", errors.New("public key is not rsa")
	}

	enc, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, rsaPub, []byte(plainText), nil)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(enc), nil
}

// DecryptWithPrivateKey 使用指定的 RSA 私钥解密 Base64 编码的密文字符串，返回明文字符串。
func (c *CryptoUtils) DecryptWithPrivateKey(cipherText string, privateKey []byte) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(cipherText)
	if err != nil {
		return "", err
	}

	block, _ := pem.Decode(privateKey)
	if block == nil {
		return "", errors.New("invalid private key pem")
	}

	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return "", err
	}

	rsaPriv, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return "", errors.New("private key is not rsa")
	}

	plain, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, rsaPriv, raw, nil)
	if err != nil {
		return "", err
	}

	return string(plain), nil
}
