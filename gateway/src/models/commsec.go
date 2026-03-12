package models

import (
	"time"

	"github.com/google/uuid"
)

type CommKeyOwnerType string
type CommKeyStatus string
type KeyExchangeAlgorithm string
type SignatureAlgorithm string
type CipherSuite string
type HandshakeStatus string
type SecureChannelStatus string

const (
	CommKeyOwnerService  CommKeyOwnerType = "service"
	CommKeyOwnerInstance CommKeyOwnerType = "instance"
)

const (
	CommKeyActive  CommKeyStatus = "active"
	CommKeyExpired CommKeyStatus = "expired"
	CommKeyRevoked CommKeyStatus = "revoked"
)

const (
	KeyExchangeECDHEP256   KeyExchangeAlgorithm = "ecdhe_p256"
	KeyExchangeECDHEX25519 KeyExchangeAlgorithm = "ecdhe_x25519"
)

const (
	SignatureECDSAP256SHA256 SignatureAlgorithm = "ecdsa_p256_sha256"
	SignatureEd25519         SignatureAlgorithm = "ed25519"
)

const (
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

// ServiceKeyOwner 标识通信密钥属于哪一个服务实体或实例。
type ServiceKeyOwner struct {
	OwnerType    CommKeyOwnerType
	ServiceID    string
	ServiceName  string
	InstanceID   string
	InstanceName string
}

// ServicePublicKeyRecord 表示存储在全局数据库中的服务通信公钥记录。
type ServicePublicKeyRecord struct {
	KeyID string
	Owner ServiceKeyOwner

	KeyExchangeAlgorithm KeyExchangeAlgorithm
	SignatureAlgorithm   SignatureAlgorithm
	PublicKeyPEM         string
	Fingerprint          string

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

	KeyExchangeAlgorithm KeyExchangeAlgorithm
	SignatureAlgorithm   SignatureAlgorithm

	PrivateKeyRef string
	LoadedAt      time.Time
}

// ECDHEHandshakeRecord 表示一次基于服务公钥认证的 ECDHE 握手过程。
type ECDHEHandshakeRecord struct {
	ID uuid.UUID

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
