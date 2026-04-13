package commsec

import (
	"strings"
	"time"
)

type CommKeyStatus string      // 通信密钥状态
type SignatureAlgorithm string // 签名算法
type CipherSuite string        // 密码套件

const (
	CommKeyActive  CommKeyStatus = "active"
	CommKeyExpired CommKeyStatus = "expired"
	CommKeyRevoked CommKeyStatus = "revoked"
)

const (
	SignatureECDSAP256SHA256 SignatureAlgorithm = "ecdsa_p256_sha256"
	SignatureEd25519         SignatureAlgorithm = "ed25519"
	SignatureRSAPSSSHA256    SignatureAlgorithm = "rsa_pss_sha256"
)

const (
	CipherSuiteAES128GCM        CipherSuite = "aes_128_gcm"
	CipherSuiteAES256GCM        CipherSuite = "aes_256_gcm"
	CipherSuiteChaCha20Poly1305 CipherSuite = "chacha20_poly1305"
)

// ServiceKeyOwner 标识通信密钥属于哪一个实体或实例。
// 统一使用 entity 语义字段，避免 service/entity 双轨冗余。
type ServiceKeyOwner struct {
	EntityType   string
	EntityID     string
	EntityName   string
	InstanceID   string
	InstanceName string
}

func (o ServiceKeyOwner) EffectiveEntityID() string {
	return o.EntityID
}

func (o ServiceKeyOwner) EffectiveEntityName() string {
	if o.EntityName != "" {
		return o.EntityName
	}
	return o.EntityID
}

func (o ServiceKeyOwner) Normalized() ServiceKeyOwner {
	o.EntityType = strings.ToLower(strings.TrimSpace(o.EntityType))
	o.EntityID = strings.TrimSpace(o.EntityID)
	o.EntityName = strings.TrimSpace(o.EntityName)
	o.InstanceID = strings.TrimSpace(o.InstanceID)
	o.InstanceName = strings.TrimSpace(o.InstanceName)
	if o.EntityName == "" {
		o.EntityName = o.EntityID
	}
	return o
}

// ServicePublicKeyRecord 表示存储在全局数据库中的实体通信公钥记录。
type ServicePublicKeyRecord struct {
	KeyID        string
	Owner        ServiceKeyOwner
	PublicKeyPEM string
	Fingerprint  string

	Status CommKeyStatus

	CreatedAt   time.Time
	ActivatedAt time.Time
	ExpiresAt   time.Time
	RevokedAt   time.Time
}

// LocalPrivateKeyRef 描述服务本地持有的私钥引用信息。
// 私钥本体不应进入数据库，只在本地安全存储中持有。
type LocalPrivateKeyRef struct {
	KeyID string
	Owner ServiceKeyOwner

	PrivateKeyRef string
	LoadedAt      time.Time
}

// PublicKeyLookupResult 是公钥目录查询结果。
type PublicKeyLookupResult struct {
	Found     bool
	Key       ServicePublicKeyRecord
	MatchedBy string

	FailureReason string
	CheckedAt     time.Time
}

// PublicKeyLookupRequest 表示统一的公钥目录查询请求。
type PublicKeyLookupRequest struct {
	KeyID string

	EntityID      string
	Owner         *ServiceKeyOwner
	RequireActive bool
}

func (r PublicKeyLookupRequest) Normalized() PublicKeyLookupRequest {
	r.KeyID = strings.TrimSpace(r.KeyID)
	r.EntityID = strings.TrimSpace(r.EntityID)
	if r.Owner != nil {
		normalizedOwner := r.Owner.Normalized()
		r.Owner = &normalizedOwner
		if r.EntityID == "" {
			r.EntityID = normalizedOwner.EffectiveEntityID()
		}
	}
	return r
}
