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

// ChannelEncryptRequest 表示基于安全通道加密应用层负载的请求。
type ChannelEncryptRequest struct {
	ChannelID      uuid.UUID
	PlainText      string
	AdditionalData map[string]string
}

// ChannelEncryptResult 表示加密结果和用于传输的元数据。
type ChannelEncryptResult struct {
	CipherText string
	Meta       EncryptedMessageMeta
}

// ChannelDecryptRequest 表示基于安全通道解密应用层负载的请求。
type ChannelDecryptRequest struct {
	ChannelID      uuid.UUID
	CipherText     string
	Sequence       uint64
	AdditionalData map[string]string
}
