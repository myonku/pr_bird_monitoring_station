package orchestration

import (
	"context"
	"time"

	commonif "certification_server/src/iface/common"
	authmodel "certification_server/src/models/auth"
)

// DownstreamGrantRequest 定义网关申请下游服务授权参数。
type DownstreamGrantRequest struct {
	Identity authmodel.IdentityContext

	TargetService string
	TTLSec        int64
}

// UserPasswordAuthRequest 定义客户端用户通过用户名/密码发起认证的参数。
type UserPasswordAuthRequest struct {
	Username string
	Password string

	Audience string
	Scopes   []string

	ClientID  string
	GatewayID string
	SourceIP  string
	UserAgent string

	RequestID string
	TraceID   string
}

// UserPasswordAuthResult 定义用户名/密码认证成功后的统一返回结果。
type UserPasswordAuthResult struct {
	Identity *authmodel.IdentityContext
	Session  *authmodel.Session
	Tokens   authmodel.TokenBundle

	IssuedAt  time.Time
	ExpiresAt time.Time
}

// IAuthRequestOrchestrator 定义 certification_server 的顶层认证请求编排。
//
// 下游接口调用：
//   - authcontrol.IInboundAuthControl.EnforceInbound
//   - common.IKeyManager.LookupPublicKey / GetPublicKey
//   - common.ISessionManager.CreateSession / ValidateSession / RevokeSession
//   - common.ITokenManager.IssueTokenBundle / VerifyToken / RefreshTokenBundle / RevokeToken
type IAuthRequestOrchestrator interface {
	HandleBootstrapChallenge(ctx context.Context, req *authmodel.ChallengeRequest) (*authmodel.ChallengePayload, error)
	HandleBootstrapAuthenticate(ctx context.Context, req *authmodel.BootstrapAuthRequest) (*authmodel.BootstrapAuthResult, error)

	HandleUserPasswordAuth(ctx context.Context, req *UserPasswordAuthRequest) (*UserPasswordAuthResult, error)

	HandleTokenVerify(ctx context.Context, req *commonif.TokenVerifyRequest) (*authmodel.TokenVerificationResult, error)
	HandleSessionValidate(ctx context.Context, req *commonif.SessionValidateRequest) (*authmodel.Session, error)

	HandleTokenRefresh(ctx context.Context, req *commonif.TokenRefreshRequest) (*authmodel.TokenBundle, error)
	HandleTokenRevoke(ctx context.Context, req *commonif.TokenRevokeRequest) error

	HandleDownstreamGrant(ctx context.Context, req *DownstreamGrantRequest) (*authmodel.DownstreamAccessGrant, error)
}
