package communication

import (
	"context"

	commsecmodel "certification_server/src/models/commsec"

	"github.com/google/uuid"
)

// SecureChannelEnsureRequest 是认证侧的通道确保请求契约。
type SecureChannelEnsureRequest struct {
	Query *SecureChannelQuery

	HandshakeInit *ECDHEHandshakeInitRequest

	RequireActive    bool
	ForceReHandshake bool
}

// ECDHEHandshakeInitRequest 表示通信层的 ECDHE 握手初始化请求。
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

// ECDHEHandshakeInitResult 表示通信层的 ECDHE 握手初始化结果。
type ECDHEHandshakeInitResult struct {
	Handshake commsecmodel.ECDHEHandshakeRecord

	SelectedKeyExchange commsecmodel.KeyExchangeAlgorithm
	SelectedSignature   commsecmodel.SignatureAlgorithm
	SelectedCipherSuite commsecmodel.CipherSuite
}

// ECDHEHandshakeCompleteRequest 表示通信层的 ECDHE 握手完成请求。
type ECDHEHandshakeCompleteRequest struct {
	HandshakeID uuid.UUID

	ResponderEphemeralPublicKey string
	ResponderSignature          string
	ResponderNonce              string
}

// ECDHEHandshakeCompleteResult 是通信层的 ECDHE 握手完成结果。
type ECDHEHandshakeCompleteResult struct {
	Handshake commsecmodel.ECDHEHandshakeRecord
	Channel   *commsecmodel.SecureChannelSession
}

// SecureChannelUpsertRequest 是认证侧的通道创建/更新请求契约。
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

// SecureChannelQuery 是通信层的通道查询契约。
type SecureChannelQuery struct {
	ChannelID    uuid.UUID
	Binding      commsecmodel.SecureChannelBinding
	ChannelClass commsecmodel.ChannelClass

	SourceEntityID string
	TargetEntityID string
}

// SecureChannelRevokeRequest 是认证侧的通道撤销请求契约。
type SecureChannelRevokeRequest struct {
	ChannelID uuid.UUID

	Binding   commsecmodel.SecureChannelBinding
	Reason    string
	RevokedBy string
}

// ChannelEncryptRequest 是通信层的载荷加密请求契约。
type ChannelEncryptRequest struct {
	ChannelID      uuid.UUID
	PlainText      string
	AdditionalData map[string]string
}

// ChannelEncryptResult 表示通信层的载荷加密结果。
type ChannelEncryptResult struct {
	CipherText string
	Meta       commsecmodel.EncryptedMessageMeta
}

// ChannelDecryptRequest 是通信层的载荷解密请求契约。
type ChannelDecryptRequest struct {
	ChannelID      uuid.UUID
	CipherText     string
	Sequence       uint64
	AdditionalData map[string]string
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

	EncryptPayload(ctx context.Context, req *ChannelEncryptRequest) (*ChannelEncryptResult, error)
	DecryptPayload(ctx context.Context, req *ChannelDecryptRequest) (string, error)
}
