package commsec

import (
	"database/sql"
	"time"

	"github.com/google/uuid"
)

type CommKeyOwnerType string     // 通信密钥所有者类型
type CommKeyStatus string        // 通信密钥状态
type KeyExchangeAlgorithm string // 密钥交换算法
type SignatureAlgorithm string   // 签名算法
type CipherSuite string          // 密码套件
type HandshakeStatus string      // 握手状态
type SecureChannelStatus string  // 安全通道状态
type ChannelBindingType string   // 通道绑定类型

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

// PublicKeyLookupRequest 表示按服务或 key id 查询通信公钥目录。
type PublicKeyLookupRequest struct {
	ServiceID   string
	ServiceName string
	KeyID       string
}

// PublicKeyLookupResult 是公钥目录查询结果。
type PublicKeyLookupResult struct {
	Found bool
	Key   ServicePublicKeyRecord

	FailureReason string
	CheckedAt     time.Time
}

// HandshakeRow 表示数据库中 commsec 握手记录的行结构。
type HandshakeRow struct {
	ID                          string       `db:"id"`
	InitiatorOwnerType          string       `db:"initiator_owner_type"`
	InitiatorServiceID          string       `db:"initiator_service_id"`
	InitiatorServiceName        string       `db:"initiator_service_name"`
	InitiatorInstanceID         string       `db:"initiator_instance_id"`
	InitiatorInstanceName       string       `db:"initiator_instance_name"`
	ResponderOwnerType          string       `db:"responder_owner_type"`
	ResponderServiceID          string       `db:"responder_service_id"`
	ResponderServiceName        string       `db:"responder_service_name"`
	ResponderInstanceID         string       `db:"responder_instance_id"`
	ResponderInstanceName       string       `db:"responder_instance_name"`
	InitiatorKeyID              string       `db:"initiator_key_id"`
	ResponderKeyID              string       `db:"responder_key_id"`
	KeyExchangeAlgorithm        string       `db:"key_exchange_algorithm"`
	SignatureAlgorithm          string       `db:"signature_algorithm"`
	CipherSuite                 string       `db:"cipher_suite"`
	InitiatorEphemeralPublicKey string       `db:"initiator_ephemeral_public_key"`
	ResponderEphemeralPublicKey string       `db:"responder_ephemeral_public_key"`
	InitiatorNonce              string       `db:"initiator_nonce"`
	ResponderNonce              string       `db:"responder_nonce"`
	InitiatorSignature          string       `db:"initiator_signature"`
	ResponderSignature          string       `db:"responder_signature"`
	Status                      string       `db:"status"`
	FailureReason               string       `db:"failure_reason"`
	StartedAt                   time.Time    `db:"started_at"`
	CompletedAt                 sql.NullTime `db:"completed_at"`
	ExpiresAt                   time.Time    `db:"expires_at"`
	UpdatedAt                   sql.NullTime `db:"updated_at"`
}

// ChannelRow 表示数据库中 commsec 安全通道记录的行结构。
type ChannelRow struct {
	ID                 string         `db:"id"`
	HandshakeID        string         `db:"handshake_id"`
	BindingType        string         `db:"binding_type"`
	BindingSessionID   sql.NullString `db:"binding_session_id"`
	BindingTokenID     sql.NullString `db:"binding_token_id"`
	BindingFamilyID    sql.NullString `db:"binding_family_id"`
	SourceOwnerType    string         `db:"source_owner_type"`
	SourceServiceID    string         `db:"source_service_id"`
	SourceServiceName  string         `db:"source_service_name"`
	SourceInstanceID   string         `db:"source_instance_id"`
	SourceInstanceName string         `db:"source_instance_name"`
	TargetOwnerType    string         `db:"target_owner_type"`
	TargetServiceID    string         `db:"target_service_id"`
	TargetServiceName  string         `db:"target_service_name"`
	TargetInstanceID   string         `db:"target_instance_id"`
	TargetInstanceName string         `db:"target_instance_name"`
	LocalKeyID         string         `db:"local_key_id"`
	PeerKeyID          string         `db:"peer_key_id"`
	CipherSuite        string         `db:"cipher_suite"`
	Status             string         `db:"status"`
	DerivedKeyRef      string         `db:"derived_key_ref"`
	Sequence           uint64         `db:"seq_no"`
	EstablishedAt      time.Time      `db:"established_at"`
	LastUsedAt         time.Time      `db:"last_used_at"`
	ExpiresAt          time.Time      `db:"expires_at"`
	RevokedAt          sql.NullTime   `db:"revoked_at"`
}
