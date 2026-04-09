package orchestration

import (
	"context"

	commonif "certification_server/src/iface/common"
	communicationif "certification_server/src/iface/communication"
	authmodel "certification_server/src/models/auth"
)

// IAuthRequestOrchestrator 定义 certification_server 的顶层认证请求编排。
//
// 下游接口调用：
//   - authcontrol.IInboundAuthControl.EnforceInbound
//   - common.IKeyManager.LookupPublicKey / GetPublicKey
//   - common.ISessionManager.CreateSession / ValidateSession / RevokeSession
//   - common.ITokenManager.IssueTokenBundle / VerifyToken / RefreshTokenBundle / RevokeToken
//   - communication.ICommsecChannelManager.EnsureChannel（用于需要安全通道的流程）
type IAuthRequestOrchestrator interface {
	HandleBootstrapChallenge(ctx context.Context, req *authmodel.ChallengeRequest) (*authmodel.ChallengePayload, error)
	HandleBootstrapAuthenticate(ctx context.Context, req *authmodel.BootstrapAuthRequest) (*authmodel.BootstrapAuthResult, error)

	HandleUserPasswordAuth(ctx context.Context, req *communicationif.UserPasswordAuthRequest) (*communicationif.UserPasswordAuthResult, error)

	HandleTokenVerify(ctx context.Context, req *commonif.TokenVerifyRequest) (*authmodel.TokenVerificationResult, error)
	HandleSessionValidate(ctx context.Context, req *commonif.SessionValidateRequest) (*authmodel.Session, error)

	HandleTokenRefresh(ctx context.Context, req *commonif.TokenRefreshRequest) (*authmodel.TokenBundle, error)
	HandleTokenRevoke(ctx context.Context, req *commonif.TokenRevokeRequest) error

	HandleDownstreamGrant(ctx context.Context, req *communicationif.DownstreamGrantRequest) (*authmodel.DownstreamAccessGrant, error)
}
