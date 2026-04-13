package authcontrol

import (
	"context"
	"time"

	authmodel "gateway/src/models/auth"
)

// DownstreamGrantRequest 定义网关申请下游授权请求。
type DownstreamGrantRequest struct {
	Identity authmodel.IdentityContext

	TargetService string
	TTLSec        int64
}

// UserPasswordAuthRequest 定义用户名密码认证请求。
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

// UserPasswordAuthResult 定义用户名密码认证结果。
type UserPasswordAuthResult struct {
	Identity *authmodel.IdentityContext
	Session  *authmodel.Session
	Tokens   authmodel.TokenBundle

	IssuedAt  time.Time
	ExpiresAt time.Time
}

// IAuthAuthorityClient 定义网关侧对认证中心的客户端调用。
type IAuthAuthorityClient interface {
	InitBootstrapChallenge(ctx context.Context, req *authmodel.ChallengeRequest) (*authmodel.ChallengePayload, error)
	AuthenticateBootstrap(ctx context.Context, req *authmodel.BootstrapAuthRequest) (*authmodel.BootstrapAuthResult, error)

	VerifyToken(ctx context.Context, req *TokenVerifyRequest) (*authmodel.TokenVerificationResult, error)
	ValidateSession(ctx context.Context, req *SessionValidateRequest) (*authmodel.Session, error)
	IssueDownstreamGrant(ctx context.Context, req *DownstreamGrantRequest) (*authmodel.DownstreamAccessGrant, error)

	AuthenticateUserPassword(ctx context.Context, req *UserPasswordAuthRequest) (*UserPasswordAuthResult, error)
	RefreshTokenBundle(ctx context.Context, req *TokenRefreshRequest) (*authmodel.TokenBundle, error)
	RevokeToken(ctx context.Context, req *TokenRevokeRequest) error
}
