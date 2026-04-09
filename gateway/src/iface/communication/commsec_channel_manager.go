package communication

import (
	"context"

	commsecmodel "gateway/src/models/commsec"

	"github.com/google/uuid"
)

// ECDHEHandshakeInitRequest 是通信层 ECDHE 初始化请求契约。
type ECDHEHandshakeInitRequest struct {
	ChannelClass commsecmodel.ChannelClass
	SecurityMode commsecmodel.ChannelSecurityMode

	Initiator commsecmodel.ServiceKeyOwner
	Responder commsecmodel.ServiceKeyOwner

	InitiatorKeyID string

	SupportedKeyExchanges []commsecmodel.KeyExchangeAlgorithm
	SupportedSignatures   []commsecmodel.SignatureAlgorithm
	SupportedCipherSuites []commsecmodel.CipherSuite

	Binding commsecmodel.SecureChannelBinding
	TTLSec  int64
}

// ECDHEHandshakeInitResult 是通信层 ECDHE 初始化结果契约。
type ECDHEHandshakeInitResult struct {
	Handshake commsecmodel.ECDHEHandshakeRecord

	SelectedKeyExchange commsecmodel.KeyExchangeAlgorithm
	SelectedSignature   commsecmodel.SignatureAlgorithm
	SelectedCipherSuite commsecmodel.CipherSuite
}

// ECDHEHandshakeCompleteRequest 是通信层 ECDHE 完成请求契约。
type ECDHEHandshakeCompleteRequest struct {
	HandshakeID uuid.UUID

	ResponderEphemeralPublicKey string
	ResponderSignature          string
	ResponderNonce              string
}

// ECDHEHandshakeCompleteResult 是通信层 ECDHE 完成结果契约。
type ECDHEHandshakeCompleteResult struct {
	Handshake commsecmodel.ECDHEHandshakeRecord
	Channel   *commsecmodel.SecureChannelSession
}

// SecureChannelUpsertRequest 是通信层通道写入请求契约。
type SecureChannelUpsertRequest struct {
	HandshakeID  uuid.UUID
	ChannelClass commsecmodel.ChannelClass
	SecurityMode commsecmodel.ChannelSecurityMode
	Binding      commsecmodel.SecureChannelBinding

	Source commsecmodel.ServiceKeyOwner
	Target commsecmodel.ServiceKeyOwner

	LocalKeyID string
	PeerKeyID  string

	CipherSuite   commsecmodel.CipherSuite
	DerivedKeyRef string
	TTLSec        int64
}

// SecureChannelQuery 是通信层通道查询请求契约。
type SecureChannelQuery struct {
	ChannelID    uuid.UUID
	Binding      commsecmodel.SecureChannelBinding
	ChannelClass commsecmodel.ChannelClass

	SourceEntityID string
	TargetEntityID string
}

// SecureChannelRevokeRequest 是通信层通道撤销请求契约。
type SecureChannelRevokeRequest struct {
	ChannelID uuid.UUID

	Binding   commsecmodel.SecureChannelBinding
	Reason    string
	RevokedBy string
}

// EncryptForChannelRequest 是按通道加密请求契约。
type EncryptForChannelRequest struct {
	ChannelID uuid.UUID
	Payload   string

	AdditionalData map[string]string
	SequenceHint   uint64
}

// DecryptFromChannelRequest 是按通道解密请求契约。
type DecryptFromChannelRequest struct {
	ChannelID  uuid.UUID
	CipherText string
	Meta       commsecmodel.EncryptedMessageMeta
}

// DecryptedPayload 是按通道解密结果契约。
type DecryptedPayload struct {
	Payload         string
	ChannelID       uuid.UUID
	UpdatedSequence uint64
}

// ICommsecChannelManager 定义安全通道生命周期与载荷操作。
//
// 下游接口调用：
//   - common.IKeyManager.GetPrivateKeyRef / LookupPublicKey
//   - commsec 服务实现使用的密码学原语
type ICommsecChannelManager interface {
	EnsureChannel(ctx context.Context, req *SecureChannelEnsureRequest) (*commsecmodel.SecureChannelSession, error)

	InitHandshake(ctx context.Context, req *ECDHEHandshakeInitRequest) (*ECDHEHandshakeInitResult, error)
	CompleteHandshake(ctx context.Context, req *ECDHEHandshakeCompleteRequest) (*ECDHEHandshakeCompleteResult, error)

	UpsertChannel(ctx context.Context, req *SecureChannelUpsertRequest) (*commsecmodel.SecureChannelSession, error)
	GetChannel(ctx context.Context, query *SecureChannelQuery) (*commsecmodel.SecureChannelSession, error)
	RevokeChannel(ctx context.Context, req *SecureChannelRevokeRequest) error

	EncryptPayload(ctx context.Context, req *EncryptForChannelRequest) (*EncryptedPayload, error)
	DecryptPayload(ctx context.Context, req *DecryptFromChannelRequest) (*DecryptedPayload, error)
}
