package commsec

import (
	"strings"
	"time"

	"github.com/google/uuid"
)

type CommKeyStatus string        // 通信密钥状态
type KeyExchangeAlgorithm string // 密钥交换算法
type SignatureAlgorithm string   // 签名算法
type CipherSuite string          // 密码套件
type HandshakeStatus string      // 握手状态
type SecureChannelStatus string  // 安全通道状态
type ChannelBindingType string   // 通道绑定类型
type ChannelClass string         // 逻辑通道类型（认证/业务）
type ChannelSecurityMode string  // 通道安全策略

const (
	CommKeyActive  CommKeyStatus = "active"
	CommKeyExpired CommKeyStatus = "expired"
	CommKeyRevoked CommKeyStatus = "revoked"
)

const (
	KeyExchangeECDHEP256   KeyExchangeAlgorithm = "ecdhe_p256"
	KeyExchangeECDHEP384   KeyExchangeAlgorithm = "ecdhe_p384"
	KeyExchangeECDHEX25519 KeyExchangeAlgorithm = "ecdhe_x25519"
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

const (
	HandshakePending     HandshakeStatus = "pending"
	HandshakeEstablished HandshakeStatus = "established"
	HandshakeFailed      HandshakeStatus = "failed"
	HandshakeExpired     HandshakeStatus = "expired"
)

const (
	SecureChannelActive  SecureChannelStatus = "active"
	SecureChannelExpired SecureChannelStatus = "expired"
	SecureChannelRevoked SecureChannelStatus = "revoked"
)

const (
	ChannelBindingToken   ChannelBindingType = "token"
	ChannelBindingSession ChannelBindingType = "session"
)

const (
	ChannelClassAuth     ChannelClass = "auth"
	ChannelClassBusiness ChannelClass = "business"
)

const (
	ChannelSecurityRequired ChannelSecurityMode = "required"
	ChannelSecurityOptional ChannelSecurityMode = "optional"
	ChannelSecurityDisabled ChannelSecurityMode = "disabled"
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

// ECDHEHandshakeRecord 表示一次基于服务公钥认证的 ECDHE 握手过程。
type ECDHEHandshakeRecord struct {
	ID uuid.UUID

	ChannelClass ChannelClass
	SecurityMode ChannelSecurityMode

	Initiator ServiceKeyOwner
	Responder ServiceKeyOwner

	InitiatorKeyID string
	ResponderKeyID string

	KeyExchangeAlgorithm KeyExchangeAlgorithm
	SignatureAlgorithm   SignatureAlgorithm
	CipherSuite          CipherSuite

	InitiatorEphemeralPublicKey string
	ResponderEphemeralPublicKey string

	InitiatorNonce string
	ResponderNonce string

	InitiatorSignature string
	ResponderSignature string

	Status        HandshakeStatus
	FailureReason string

	StartedAt   time.Time
	CompletedAt time.Time
	ExpiresAt   time.Time
}

// SecureChannelBinding 表示应用层加密通道挂靠在哪个本地认证对象上。
type SecureChannelBinding struct {
	BindingType   ChannelBindingType
	SessionID     uuid.UUID
	TokenID       uuid.UUID
	TokenFamilyID uuid.UUID
}

// SecureChannelSession 表示握手完成后在本地缓存中的对称密钥状态。
// DerivedKeyRef 指向本地缓存或内存槽位，不建议直接持久化原始对称密钥。
type SecureChannelSession struct {
	ID uuid.UUID

	ChannelClass ChannelClass
	SecurityMode ChannelSecurityMode

	HandshakeID uuid.UUID
	Binding     SecureChannelBinding

	Source ServiceKeyOwner
	Target ServiceKeyOwner

	LocalKeyID string
	PeerKeyID  string

	CipherSuite CipherSuite
	Status      SecureChannelStatus

	DerivedKeyRef string
	Sequence      uint64
	EstablishedAt time.Time
	LastUsedAt    time.Time
	ExpiresAt     time.Time
	RevokedAt     time.Time
}

// EncryptedMessageMeta 是后续写入 gRPC metadata 的应用层加密元数据。
type EncryptedMessageMeta struct {
	ChannelID      uuid.UUID
	HandshakeID    uuid.UUID
	KeyID          string
	CipherSuite    CipherSuite
	Sequence       uint64
	Nonce          string
	AdditionalData map[string]string
	IssuedAt       time.Time
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

// PublicKeyLookupResult 是公钥目录查询结果。
type PublicKeyLookupResult struct {
	Found     bool
	Key       ServicePublicKeyRecord
	MatchedBy string

	FailureReason string
	CheckedAt     time.Time
}
