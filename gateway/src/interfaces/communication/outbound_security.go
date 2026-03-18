package communication

import (
	"context"
	authmodel "gateway/src/models/auth"
	commsecmodel "gateway/src/models/commsec"
)

// OutboundInvocationRequest 表示一次主动发起内部调用的安全准备输入。
type OutboundInvocationRequest struct {
	GrantRequest *authmodel.DownstreamGrantRequest
	ChannelQuery *commsecmodel.SecureChannelQuery

	HandshakeInit *commsecmodel.ECDHEHandshakeInitRequest

	Payload        string
	AdditionalData map[string]string

	RequireEncryptedPayload bool
}

// OutboundInvocationContext 表示一次主动调用准备完成后的统一安全上下文。
type OutboundInvocationContext struct {
	Grant      *authmodel.DownstreamAccessGrant
	Channel    *commsecmodel.SecureChannelSession
	CipherText string
	Meta       *commsecmodel.EncryptedMessageMeta
}

// IOutboundAuthCoordinator 负责主动调用链路中的认证编排。
// 引用: gateway/src/interfaces/auth/bootstrap_flow.go, gateway/src/interfaces/auth/downstream_grant_client.go。
type IOutboundAuthCoordinator interface {
	EnsureBootstrapReady(ctx context.Context, req *authmodel.ChallengeRequest) (*authmodel.BootstrapAuthResult, error)
	IssueDownstreamGrant(ctx context.Context, req *authmodel.DownstreamGrantRequest) (*authmodel.DownstreamAccessGrant, error)
}

// IOutboundChannelCoordinator 负责主动调用链路中的通道编排与载荷加密。
// 引用: gateway/src/interfaces/commsec/commsec_svc.go。
type IOutboundChannelCoordinator interface {
	EnsureChannel(ctx context.Context, req *commsecmodel.SecureChannelEnsureRequest) (*commsecmodel.SecureChannelSession, error)
	EncryptForChannel(ctx context.Context, req *commsecmodel.EncryptForChannelRequest) (*commsecmodel.EncryptedPayload, error)
}

// IOutboundInvocationSecurity 负责把 auth 与 commsec 组合成一次可执行的出站安全准备。
// 引用: RFC 5116 (AEAD), RFC 8446 (协商套件驱动加密参数), gRPC Metadata 约定。
type IOutboundInvocationSecurity interface {
	Prepare(ctx context.Context, req *OutboundInvocationRequest) (*OutboundInvocationContext, error)
}
