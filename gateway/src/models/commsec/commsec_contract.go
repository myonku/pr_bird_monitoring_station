package commsec

import "github.com/google/uuid"

// ECDHEHandshakeInitRequest 表示 ECDHE 握手初始化请求。
type ECDHEHandshakeInitRequest struct {
	Initiator ServiceKeyOwner
	Responder ServiceKeyOwner

	InitiatorKeyID string

	SupportedKeyExchanges []KeyExchangeAlgorithm
	SupportedSignatures   []SignatureAlgorithm
	SupportedCipherSuites []CipherSuite

	Binding SecureChannelBinding
	TTLSec  int64
}

// ECDHEHandshakeInitResult 表示握手初始化结果。
type ECDHEHandshakeInitResult struct {
	Handshake ECDHEHandshakeRecord

	SelectedKeyExchange KeyExchangeAlgorithm
	SelectedSignature   SignatureAlgorithm
	SelectedCipherSuite CipherSuite
}

// ECDHEHandshakeCompleteRequest 表示 ECDHE 握手完成请求。
type ECDHEHandshakeCompleteRequest struct {
	HandshakeID uuid.UUID

	ResponderEphemeralPublicKey string
	ResponderSignature          string
	ResponderNonce              string
}

// ECDHEHandshakeCompleteResult 表示 ECDHE 握手完成结果。
type ECDHEHandshakeCompleteResult struct {
	Handshake ECDHEHandshakeRecord
	Channel   *SecureChannelSession
}

// SecureChannelUpsertRequest 表示建立或更新通道缓存请求。
type SecureChannelUpsertRequest struct {
	HandshakeID uuid.UUID
	Binding     SecureChannelBinding

	Source ServiceKeyOwner
	Target ServiceKeyOwner

	LocalKeyID string
	PeerKeyID  string

	CipherSuite   CipherSuite
	DerivedKeyRef string
	TTLSec        int64
}

// SecureChannelQuery 表示通道查询条件。
type SecureChannelQuery struct {
	ChannelID uuid.UUID
	Binding   SecureChannelBinding

	SourceServiceID string
	TargetServiceID string
}

// SecureChannelRevokeRequest 表示撤销通道请求。
type SecureChannelRevokeRequest struct {
	ChannelID uuid.UUID

	Binding   SecureChannelBinding
	Reason    string
	RevokedBy string
}

// SecureChannelEnsureRequest 表示“主动通信方”在出站前确保通道可用的请求。
type SecureChannelEnsureRequest struct {
	Query SecureChannelQuery

	HandshakeInit *ECDHEHandshakeInitRequest

	RequireActive    bool
	ForceReHandshake bool
}

// EncryptForChannelRequest 表示基于指定安全通道进行加密的请求。
type EncryptForChannelRequest struct {
	ChannelID uuid.UUID
	Payload   string

	AdditionalData map[string]string
	SequenceHint   uint64
}

// EncryptedPayload 表示应用层加密后的载荷和元数据。
type EncryptedPayload struct {
	CipherText string
	Meta       EncryptedMessageMeta
}

// DecryptFromChannelRequest 表示基于指定安全通道进行解密的请求。
type DecryptFromChannelRequest struct {
	ChannelID  uuid.UUID
	CipherText string
	Meta       EncryptedMessageMeta
}

// DecryptedPayload 表示解密后的明文以及更新后的通道状态信息。
type DecryptedPayload struct {
	Payload         string
	ChannelID       uuid.UUID
	UpdatedSequence uint64
}
