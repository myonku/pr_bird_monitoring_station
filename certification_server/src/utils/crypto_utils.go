package utils

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
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

// EncryptWithSymmetricKeyAndAAD 使用 AES-GCM 对称加密并支持附加认证数据。
func (c *CryptoUtils) EncryptWithSymmetricKeyAndAAD(plainText string, key []byte, aad []byte) (string, error) {
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

	cipherBytes := gcm.Seal(nil, nonce, []byte(plainText), aad)
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

// DecryptWithSymmetricKeyAndAAD 使用 AES-GCM 对称解密并校验附加认证数据。
func (c *CryptoUtils) DecryptWithSymmetricKeyAndAAD(cipherText string, key []byte, aad []byte) (string, error) {
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
	plain, err := gcm.Open(nil, nonce, cipherBytes, aad)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}

// EncryptWithCipherSuite 按协商密码套件进行加密。
func (c *CryptoUtils) EncryptWithCipherSuite(cipherSuite string, plainText string, key []byte, aad []byte) (string, error) {
	switch cipherSuite {
	case "aes_128_gcm", "aes_256_gcm", "":
		return c.EncryptWithSymmetricKeyAndAAD(plainText, key, aad)
	case "chacha20_poly1305":
		aead, err := chacha20poly1305.NewX(key)
		if err != nil {
			return "", err
		}
		nonce := make([]byte, chacha20poly1305.NonceSizeX)
		if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
			return "", err
		}
		cipherBytes := aead.Seal(nil, nonce, []byte(plainText), aad)
		out := append(nonce, cipherBytes...)
		return base64.StdEncoding.EncodeToString(out), nil
	default:
		return "", fmt.Errorf("unsupported cipher suite: %s", cipherSuite)
	}
}

// DecryptWithCipherSuite 按协商密码套件进行解密。
func (c *CryptoUtils) DecryptWithCipherSuite(cipherSuite string, cipherText string, key []byte, aad []byte) (string, error) {
	switch cipherSuite {
	case "aes_128_gcm", "aes_256_gcm", "":
		return c.DecryptWithSymmetricKeyAndAAD(cipherText, key, aad)
	case "chacha20_poly1305":
		raw, err := base64.StdEncoding.DecodeString(cipherText)
		if err != nil {
			return "", err
		}
		aead, err := chacha20poly1305.NewX(key)
		if err != nil {
			return "", err
		}
		if len(raw) < chacha20poly1305.NonceSizeX {
			return "", errors.New("invalid ciphertext length")
		}
		nonce := raw[:chacha20poly1305.NonceSizeX]
		cipherBytes := raw[chacha20poly1305.NonceSizeX:]
		plain, err := aead.Open(nil, nonce, cipherBytes, aad)
		if err != nil {
			return "", err
		}
		return string(plain), nil
	default:
		return "", fmt.Errorf("unsupported cipher suite: %s", cipherSuite)
	}
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

// SignByAlgorithm 使用给定签名算法和私钥对消息签名，返回 Base64 签名串。
func (c *CryptoUtils) SignByAlgorithm(algorithm string, message []byte, privateKeyPEM []byte) (string, error) {
	privAny, err := parsePrivateKey(privateKeyPEM)
	if err != nil {
		return "", err
	}

	switch algorithm {
	case "ed25519":
		priv, ok := privAny.(ed25519.PrivateKey)
		if !ok {
			return "", errors.New("private key is not ed25519")
		}
		sig := ed25519.Sign(priv, message)
		return base64.StdEncoding.EncodeToString(sig), nil
	case "ecdsa_p256_sha256":
		priv, ok := privAny.(*ecdsa.PrivateKey)
		if !ok {
			return "", errors.New("private key is not ecdsa")
		}
		h := sha256.Sum256(message)
		sigDER, signErr := ecdsa.SignASN1(rand.Reader, priv, h[:])
		if signErr != nil {
			return "", signErr
		}
		return base64.StdEncoding.EncodeToString(sigDER), nil
	case "rsa_pss_sha256":
		priv, ok := privAny.(*rsa.PrivateKey)
		if !ok {
			return "", errors.New("private key is not rsa")
		}
		h := sha256.Sum256(message)
		sig, signErr := rsa.SignPSS(rand.Reader, priv, crypto.SHA256, h[:], nil)
		if signErr != nil {
			return "", signErr
		}
		return base64.StdEncoding.EncodeToString(sig), nil
	default:
		return "", fmt.Errorf("unsupported signature algorithm: %s", algorithm)
	}
}

// VerifyByAlgorithm 使用给定签名算法和公钥验证签名。
func (c *CryptoUtils) VerifyByAlgorithm(algorithm string, message []byte, signatureB64 string, publicKeyPEM []byte) error {
	sig, err := base64.StdEncoding.DecodeString(signatureB64)
	if err != nil {
		return err
	}

	pubAny, err := parsePublicKey(publicKeyPEM)
	if err != nil {
		return err
	}

	switch algorithm {
	case "ed25519":
		pub, ok := pubAny.(ed25519.PublicKey)
		if !ok {
			return errors.New("public key is not ed25519")
		}
		if !ed25519.Verify(pub, message, sig) {
			return errors.New("signature verification failed")
		}
		return nil
	case "ecdsa_p256_sha256":
		pub, ok := pubAny.(*ecdsa.PublicKey)
		if !ok {
			return errors.New("public key is not ecdsa")
		}
		h := sha256.Sum256(message)
		if !ecdsa.VerifyASN1(pub, h[:], sig) {
			return errors.New("signature verification failed")
		}
		return nil
	case "rsa_pss_sha256":
		pub, ok := pubAny.(*rsa.PublicKey)
		if !ok {
			return errors.New("public key is not rsa")
		}
		h := sha256.Sum256(message)
		return rsa.VerifyPSS(pub, crypto.SHA256, h[:], sig, nil)
	default:
		return fmt.Errorf("unsupported signature algorithm: %s", algorithm)
	}
}

// DeriveSessionKeyByHandshake 根据握手材料与协商参数派生会话密钥（Base64）。
func (c *CryptoUtils) DeriveSessionKeyByHandshake(
	keyExchange string,
	cipherSuite string,
	initiatorEphemeral string,
	responderEphemeral string,
	initiatorNonce string,
	responderNonce string,
) (string, error) {
	keyLen := 32
	if cipherSuite == "aes_128_gcm" {
		keyLen = 16
	}

	material := []byte(keyExchange + "|" + initiatorEphemeral + "|" + responderEphemeral + "|" + initiatorNonce + "|" + responderNonce)
	seed := sha512.Sum512(material)
	buf := make([]byte, keyLen)
	var counter uint32 = 1
	offset := 0
	for offset < keyLen {
		mac := hmac.New(sha256.New, seed[:])
		_ = binary.Write(mac, binary.BigEndian, counter)
		block := mac.Sum(nil)
		remain := keyLen - offset
		if remain > len(block) {
			remain = len(block)
		}
		copy(buf[offset:offset+remain], block[:remain])
		offset += remain
		counter++
	}
	return base64.StdEncoding.EncodeToString(buf), nil
}

func parsePrivateKey(privateKeyPEM []byte) (any, error) {
	block, _ := pem.Decode(privateKeyPEM)
	if block == nil {
		return nil, errors.New("invalid private key pem")
	}

	if keyAny, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		switch key := keyAny.(type) {
		case *rsa.PrivateKey, *ecdsa.PrivateKey, ed25519.PrivateKey:
			return key, nil
		}
	}

	if rsaKey, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return rsaKey, nil
	}

	if ecKey, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		if ecKey.Curve == nil {
			ecKey.Curve = elliptic.P256()
		}
		return ecKey, nil
	}

	return nil, errors.New("unsupported private key format")
}

func parsePublicKey(publicKeyPEM []byte) (any, error) {
	block, _ := pem.Decode(publicKeyPEM)
	if block == nil {
		return nil, errors.New("invalid public key pem")
	}
	keyAny, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	switch key := keyAny.(type) {
	case *rsa.PublicKey, *ecdsa.PublicKey, ed25519.PublicKey:
		return key, nil
	default:
		return nil, errors.New("unsupported public key type")
	}
}
