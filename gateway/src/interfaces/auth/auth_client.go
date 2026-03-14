package auth

import (
	"context"
	authmodel "gateway/src/models/auth"
)

// IAuthClient 定义网关访问认证中心的客户端接口。
// 将 bootstrap、令牌、会话、下游授权收敛到同一客户端，便于统一重试与熔断。
type IAuthClient interface {
	// Bootstrap 相关接口
	InitChallenge(ctx context.Context, req *authmodel.ChallengeRequest) (*authmodel.ChallengePayload, error)
	AuthenticateBootstrap(ctx context.Context, req *authmodel.BootstrapAuthRequest) (*authmodel.BootstrapAuthResult, error)

	// Token 相关接口
	RefreshTokenBundle(ctx context.Context, req *authmodel.TokenRefreshRequest) (*authmodel.TokenBundle, error)
	VerifyToken(ctx context.Context, req *authmodel.TokenVerifyRequest) (*authmodel.TokenVerificationResult, error)
	RevokeToken(ctx context.Context, req *authmodel.TokenRevokeRequest) error

	// Session 相关接口
	GetSession(ctx context.Context, sessionID string) (*authmodel.Session, error)
	TouchSession(ctx context.Context, sessionID string, meta authmodel.SessionTouchMeta) error
	ValidateSession(ctx context.Context, req *authmodel.SessionValidateRequest) (*authmodel.Session, error)

	// IssueDownstreamGrant 根据请求参数为下游服务签发访问授权，返回授权结果。
	IssueDownstreamGrant(ctx context.Context, req *authmodel.DownstreamGrantRequest) (*authmodel.DownstreamAccessGrant, error)
}
